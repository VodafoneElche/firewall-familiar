using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;
using Windows.Win32.Security;
using Win = Windows.Win32.PInvoke;

namespace FirewallFamiliar.Core;

/// <summary>Una conexión que el cortafuegos acaba de bloquear.</summary>
public sealed class BlockedConnection
{
    public DateTime Time { get; init; } = DateTime.Now;
    /// <summary>Ruta del programa (C:\...), "System" para el núcleo de Windows, o "" si Windows no la indica.</summary>
    public string AppPath { get; init; } = "";
    public string Protocol { get; init; } = "";
    public IPAddress? RemoteAddress { get; init; }
    public int RemotePort { get; init; }
    public int LocalPort { get; init; }
    public bool Inbound { get; init; }
    /// <summary>true si lo ha bloqueado el filtro "preguntar" (programa sin regla).</summary>
    public bool NeedsAnswer { get; init; }
    /// <summary>Qué regla lo ha bloqueado, en palabras.</summary>
    public string Reason { get; init; } = "";

    public string Remote => RemoteAddress == null ? "" : $"{RemoteAddress}:{RemotePort}";
}

/// <summary>
/// Cortafuegos basado en la Plataforma de Filtrado de Windows (WFP): la misma tecnología que usa
/// el Firewall de Windows. No necesita instalar ningún driver.
///
/// Cómo funciona:
///  - Se abre una sesión "dinámica": todos los filtros se borran solos al cerrar el programa,
///    así que si algo falla, Internet vuelve a funcionar al cerrarlo.
///  - Los filtros se agrupan en una subcapa propia. Dentro de ella gana el filtro de más peso:
///      1. Tráfico interno del equipo (localhost): siempre permitido.
///      2. "Bloquear todo".
///      3. Reglas avanzadas, por orden.
///      4. Reglas por programa (bloquear pesa más que permitir).
///      5. Permisos automáticos (componentes de Windows, este programa).
///      6. En modo "Preguntar": bloqueo por defecto de las conexiones salientes. Windows nos avisa
///         de cada bloqueo y entonces se pregunta al usuario.
///  - El tráfico de respuesta de una conexión permitida pasa solo (inspección con estado de WFP).
/// </summary>
public sealed unsafe class WfpFirewall : IDisposable
{
    private static readonly Guid SublayerKey = new("6f3a3c0e-6a1b-4b8e-9a52-6a1f0c7a2b11");
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint FWP_E_ALREADY_EXISTS = 0x80320009;

    // Indicadores de qué campos trae un evento de red (FWPM_NET_EVENT_FLAG_*)
    private const uint FLAG_IP_PROTOCOL_SET = 0x1;
    private const uint FLAG_LOCAL_PORT_SET = 0x8;
    private const uint FLAG_REMOTE_ADDR_SET = 0x4;
    private const uint FLAG_REMOTE_PORT_SET = 0x10;
    private const uint FLAG_APP_ID_SET = 0x20;

    // Pesos dentro de nuestra subcapa (gana el mayor)
    private const ulong WeightLoopback = 10_000_000;
    private const ulong WeightBlockAll = 9_000_000;
    private const ulong WeightAdvanced = 8_000_000;
    private const ulong WeightAppBlock = 5_000;
    private const ulong WeightAppPermit = 4_000;
    private const ulong WeightAutoPermit = 3_000;
    private const ulong WeightAskDefault = 1;

    private static WfpFirewall? _current;

    private HANDLE _engine;
    private HANDLE _events;
    private readonly List<ulong> _filterIds = new();
    private volatile Dictionary<ulong, FilterInfo> _filterInfo = new();
    private readonly List<(string Device, string Drive)> _devices = new();

    private sealed record FilterInfo(string Reason, bool IsAskDefault, bool Inbound);

    /// <summary>Se lanza (desde un hilo de Windows) cada vez que nuestros filtros bloquean una conexión.</summary>
    public event Action<BlockedConnection>? Blocked;

    /// <summary>
    /// Entradas desde fuera que ha bloqueado otro filtro (normalmente el Firewall de Windows),
    /// por ejemplo alguien probando puertos cerrados. Sirve para detectar escaneos.
    /// </summary>
    public event Action<BlockedConnection>? ForeignInboundBlocked;

    public bool IsOpen => _engine != default;

    /// <summary>Abre la conexión con el motor de filtrado de Windows. Lanza una excepción si falla.</summary>
    public void Open()
    {
        LoadDeviceMap();

        var session = default(FWPM_SESSION0);
        session.flags = Win.FWPM_SESSION_FLAG_DYNAMIC;
        session.txnWaitTimeoutInMSec = 5000;
        fixed (char* name = "Firewall Familiar")
        {
            session.displayData.name = new PWSTR(name);
            HANDLE engine;
            Check(Win.FwpmEngineOpen0(default, RPC_C_AUTHN_WINNT, null, &session, &engine), "abrir el motor de filtrado");
            _engine = engine;
        }

        // Pedir a Windows que registre las conexiones bloqueadas, para poder avisar al usuario.
        var on = default(FWP_VALUE0);
        on.type = FWP_DATA_TYPE.FWP_UINT32;
        on.Anonymous.uint32 = 1;
        Win.FwpmEngineSetOption0(_engine, FWPM_ENGINE_OPTION.FWPM_ENGINE_COLLECT_NET_EVENTS, &on);
        EnablePortScanEvents();

        var sublayer = default(FWPM_SUBLAYER0);
        sublayer.subLayerKey = SublayerKey;
        sublayer.weight = 0x7FFF;
        fixed (char* name = "Firewall Familiar")
        {
            sublayer.displayData.name = new PWSTR(name);
            uint r = Win.FwpmSubLayerAdd0(_engine, &sublayer, default(PSECURITY_DESCRIPTOR));
            if (r != 0 && r != FWP_E_ALREADY_EXISTS) Check(r, "crear la subcapa");
        }

        _current = this;
        var subscription = default(FWPM_NET_EVENT_SUBSCRIPTION0);
        HANDLE events;
        Check(Win.FwpmNetEventSubscribe0(_engine, &subscription, &OnNetEvent, null, &events),
            "suscribirse a los avisos de bloqueo");
        _events = events;
    }

    /// <summary>
    /// Sustituye todos nuestros filtros por los que corresponden a las reglas actuales.
    /// Se hace en una transacción: o se aplica todo o no se cambia nada.
    /// Devuelve avisos (por ejemplo, programas que ya no existen).
    /// </summary>
    public List<string> Apply(RuleSet rules, IEnumerable<string> autoPermits, IEnumerable<string> tempBlocks)
    {
        var warnings = new List<string>();
        var info = new Dictionary<ulong, FilterInfo>();
        using var mem = new Arena();

        Check(Win.FwpmTransactionBegin0(_engine, 0), "empezar los cambios");
        var previousIds = _filterIds.ToList();
        try
        {
            foreach (var id in _filterIds) Win.FwpmFilterDeleteById0(_engine, id);
            _filterIds.Clear();

            // 1. Tráfico interno (localhost): siempre permitido
            var loopback = new[] { CondLoopback() };
            foreach (var layer in AllLayers)
                Add(layer, FWP_ACTION_TYPE.FWP_ACTION_PERMIT, WeightLoopback, "Permitir tráfico interno", loopback, info, false, mem);

            // 2. Bloquear todo
            if (rules.Mode == FirewallMode.BloquearTodo)
                foreach (var layer in AllLayers)
                    Add(layer, FWP_ACTION_TYPE.FWP_ACTION_BLOCK, WeightBlockAll, "Bloquear todo", Array.Empty<FWPM_FILTER_CONDITION0>(), info, false, mem);

            // 3. Reglas avanzadas, en orden de prioridad
            int index = 0;
            foreach (var rule in rules.Advanced)
            {
                ulong weight = WeightAdvanced - (ulong)(index++ * 10);
                if (!rule.Enabled) continue;
                string? error = rule.Validate();
                if (error != null) { warnings.Add($"Regla \"{rule.Name}\" no aplicada: {error}"); continue; }
                AddAdvanced(rule, weight, info, mem, warnings);
            }

            // 4. Reglas por programa
            foreach (var app in rules.Apps)
            {
                if (app.Action == RuleAction.Preguntar) continue;
                var blob = AppIdBlob(app.Path, mem);
                if (blob == null) { warnings.Add($"No se encuentra {app.Path}: su regla no se aplica."); continue; }
                var cond = new[] { CondAppId(blob) };
                if (app.Action == RuleAction.Bloquear)
                    foreach (var layer in AllLayers)
                        Add(layer, FWP_ACTION_TYPE.FWP_ACTION_BLOCK, WeightAppBlock, "Regla: bloquear " + app.Name, cond, info, IsInbound(layer), mem);
                else
                    foreach (var layer in ConnectLayers)
                        Add(layer, FWP_ACTION_TYPE.FWP_ACTION_PERMIT, WeightAppPermit, "Regla: permitir " + app.Name, cond, info, false, mem);
            }

            foreach (var path in tempBlocks)
            {
                var blob = AppIdBlob(path, mem);
                if (blob == null) continue;
                var cond = new[] { CondAppId(blob) };
                foreach (var layer in ConnectLayers)
                    Add(layer, FWP_ACTION_TYPE.FWP_ACTION_BLOCK, WeightAppBlock, "Bloqueado en esta sesión: " + Path.GetFileName(path), cond, info, false, mem);
            }

            // 5. Permisos automáticos
            foreach (var path in autoPermits.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var blob = AppIdBlob(path, mem);
                if (blob == null) continue;
                var cond = new[] { CondAppId(blob) };
                foreach (var layer in ConnectLayers)
                    Add(layer, FWP_ACTION_TYPE.FWP_ACTION_PERMIT, WeightAutoPermit, "Permitido automáticamente: " + Path.GetFileName(path), cond, info, false, mem);
            }

            // 6. Preguntar: bloqueo por defecto de lo saliente
            if (rules.Mode == FirewallMode.Preguntar)
                foreach (var layer in ConnectLayers)
                    Add(layer, FWP_ACTION_TYPE.FWP_ACTION_BLOCK, WeightAskDefault, "Programa sin regla (preguntar)", Array.Empty<FWPM_FILTER_CONDITION0>(), info, false, mem, isAsk: true);

            Check(Win.FwpmTransactionCommit0(_engine), "guardar los cambios");
        }
        catch
        {
            // Al cancelar la transacción, Windows deja los filtros anteriores tal cual.
            Win.FwpmTransactionAbort0(_engine);
            _filterIds.Clear();
            _filterIds.AddRange(previousIds);
            throw;
        }

        _filterInfo = info;
        return warnings;
    }

    private void AddAdvanced(AdvancedRule rule, ulong weight, Dictionary<ulong, FilterInfo> info, Arena mem, List<string> warnings)
    {
        var action = rule.Action == RuleAction.Permitir ? FWP_ACTION_TYPE.FWP_ACTION_PERMIT : FWP_ACTION_TYPE.FWP_ACTION_BLOCK;
        string reason = $"Regla avanzada: {rule.Name}";

        var common = new List<FWPM_FILTER_CONDITION0>();
        if (rule.AppPath.Trim().Length > 0)
        {
            var blob = AppIdBlob(rule.AppPath.Trim(), mem);
            if (blob == null) { warnings.Add($"Regla \"{rule.Name}\": no se encuentra el programa."); return; }
            common.Add(CondAppId(blob));
        }
        if (rule.Protocol != RuleProtocol.Cualquiera)
            common.Add(CondProtocol(rule.Protocol == RuleProtocol.TCP ? (byte)6 : (byte)17));
        foreach (var (from, to) in AdvancedRule.ParsePorts(rule.RemotePorts))
            common.Add(CondPort(Win.FWPM_CONDITION_IP_REMOTE_PORT, from, to, mem));
        foreach (var (from, to) in AdvancedRule.ParsePorts(rule.LocalPorts))
            common.Add(CondPort(Win.FWPM_CONDITION_IP_LOCAL_PORT, from, to, mem));

        var addresses = AdvancedRule.ParseAddresses(rule.RemoteAddresses);
        var v4 = addresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork).ToList();
        var v6 = addresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6).ToList();

        foreach (var layer in AllLayers)
        {
            bool inbound = IsInbound(layer);
            if (inbound && rule.Direction == RuleDirection.Saliente) continue;
            if (!inbound && rule.Direction == RuleDirection.Entrante) continue;

            bool isV6 = layer == Win.FWPM_LAYER_ALE_AUTH_CONNECT_V6 || layer == Win.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
            var conds = new List<FWPM_FILTER_CONDITION0>(common);
            if (addresses.Count > 0)
            {
                var mine = isV6 ? v6 : v4;
                if (mine.Count == 0) continue; // la regla solo habla de direcciones de la otra versión de IP
                foreach (var (ip, prefix) in mine) conds.Add(CondRemoteAddress(ip, prefix, mem));
            }
            Add(layer, action, weight, reason, conds.ToArray(), info, inbound, mem);
        }
    }

    // ------------------------------------------------------------------
    // Creación de filtros y condiciones
    // ------------------------------------------------------------------

    private static readonly Guid[] AllLayers =
    {
        Win.FWPM_LAYER_ALE_AUTH_CONNECT_V4, Win.FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Win.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, Win.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
    };

    private static readonly Guid[] ConnectLayers =
    {
        Win.FWPM_LAYER_ALE_AUTH_CONNECT_V4, Win.FWPM_LAYER_ALE_AUTH_CONNECT_V6
    };

    private static bool IsInbound(Guid layer) =>
        layer == Win.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 || layer == Win.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

    private void Add(Guid layer, FWP_ACTION_TYPE action, ulong weight, string name,
        FWPM_FILTER_CONDITION0[] conditions, Dictionary<ulong, FilterInfo> info, bool inbound, Arena mem, bool isAsk = false)
    {
        var filter = default(FWPM_FILTER0);
        filter.layerKey = layer;
        filter.subLayerKey = SublayerKey;
        filter.action.type = action;

        ulong* w = (ulong*)mem.Alloc(sizeof(ulong));
        *w = weight;
        filter.weight.type = FWP_DATA_TYPE.FWP_UINT64;
        filter.weight.Anonymous.uint64 = w;

        fixed (char* n = name)
        fixed (FWPM_FILTER_CONDITION0* c = conditions)
        {
            filter.displayData.name = new PWSTR(n);
            filter.numFilterConditions = (uint)conditions.Length;
            filter.filterCondition = conditions.Length > 0 ? c : null;
            ulong id;
            Check(Win.FwpmFilterAdd0(_engine, &filter, default(PSECURITY_DESCRIPTOR), &id), "añadir el filtro \"" + name + "\"");
            _filterIds.Add(id);
            info[id] = new FilterInfo(name, isAsk, inbound);
        }
    }

    private static FWPM_FILTER_CONDITION0 CondAppId(FWP_BYTE_BLOB* blob)
    {
        var c = default(FWPM_FILTER_CONDITION0);
        c.fieldKey = Win.FWPM_CONDITION_ALE_APP_ID;
        c.matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
        c.conditionValue.type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE;
        c.conditionValue.Anonymous.byteBlob = blob;
        return c;
    }

    private static FWPM_FILTER_CONDITION0 CondLoopback()
    {
        var c = default(FWPM_FILTER_CONDITION0);
        c.fieldKey = Win.FWPM_CONDITION_FLAGS;
        c.matchType = FWP_MATCH_TYPE.FWP_MATCH_FLAGS_ALL_SET;
        c.conditionValue.type = FWP_DATA_TYPE.FWP_UINT32;
        c.conditionValue.Anonymous.uint32 = Win.FWP_CONDITION_FLAG_IS_LOOPBACK;
        return c;
    }

    private static FWPM_FILTER_CONDITION0 CondProtocol(byte protocol)
    {
        var c = default(FWPM_FILTER_CONDITION0);
        c.fieldKey = Win.FWPM_CONDITION_IP_PROTOCOL;
        c.matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
        c.conditionValue.type = FWP_DATA_TYPE.FWP_UINT8;
        c.conditionValue.Anonymous.uint8 = protocol;
        return c;
    }

    private static FWPM_FILTER_CONDITION0 CondPort(Guid field, ushort from, ushort to, Arena mem)
    {
        var c = default(FWPM_FILTER_CONDITION0);
        c.fieldKey = field;
        if (from == to)
        {
            c.matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_DATA_TYPE.FWP_UINT16;
            c.conditionValue.Anonymous.uint16 = from;
        }
        else
        {
            var range = (FWP_RANGE0*)mem.Alloc(sizeof(FWP_RANGE0));
            *range = default;
            range->valueLow.type = FWP_DATA_TYPE.FWP_UINT16;
            range->valueLow.Anonymous.uint16 = from;
            range->valueHigh.type = FWP_DATA_TYPE.FWP_UINT16;
            range->valueHigh.Anonymous.uint16 = to;
            c.matchType = FWP_MATCH_TYPE.FWP_MATCH_RANGE;
            c.conditionValue.type = FWP_DATA_TYPE.FWP_RANGE_TYPE;
            c.conditionValue.Anonymous.rangeValue = range;
        }
        return c;
    }

    private static FWPM_FILTER_CONDITION0 CondRemoteAddress(IPAddress ip, int prefix, Arena mem)
    {
        var c = default(FWPM_FILTER_CONDITION0);
        c.fieldKey = Win.FWPM_CONDITION_IP_REMOTE_ADDRESS;
        c.matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
        byte[] bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            // WFP usa las direcciones IPv4 en orden "de máquina"
            uint addr = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
            uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
            var am = (FWP_V4_ADDR_AND_MASK*)mem.Alloc(sizeof(FWP_V4_ADDR_AND_MASK));
            am->addr = addr & mask;
            am->mask = mask;
            c.conditionValue.type = FWP_DATA_TYPE.FWP_V4_ADDR_MASK;
            c.conditionValue.Anonymous.v4AddrMask = am;
        }
        else
        {
            var am = (FWP_V6_ADDR_AND_MASK*)mem.Alloc(sizeof(FWP_V6_ADDR_AND_MASK));
            *am = default;
            for (int i = 0; i < 16; i++) am->addr[i] = bytes[i];
            am->prefixLength = (byte)prefix;
            c.conditionValue.type = FWP_DATA_TYPE.FWP_V6_ADDR_MASK;
            c.conditionValue.Anonymous.v6AddrMask = am;
        }
        return c;
    }

    /// <summary>Identificador que WFP usa para un programa (su ruta en formato interno de Windows).</summary>
    private static FWP_BYTE_BLOB* AppIdBlob(string path, Arena mem)
    {
        if (string.Equals(path, "System", StringComparison.OrdinalIgnoreCase))
        {
            // El tráfico del núcleo de Windows se identifica con el texto "System"
            byte[] data = Encoding.Unicode.GetBytes("System\0");
            var blob = (FWP_BYTE_BLOB*)mem.Alloc(sizeof(FWP_BYTE_BLOB));
            blob->size = (uint)data.Length;
            blob->data = (byte*)mem.Alloc(data.Length);
            Marshal.Copy(data, 0, (IntPtr)blob->data, data.Length);
            return blob;
        }

        if (!File.Exists(path)) return null;
        FWP_BYTE_BLOB* wfpBlob = null;
        fixed (char* p = path)
        {
            if (Win.FwpmGetAppIdFromFileName0(new PCWSTR(p), &wfpBlob) != 0 || wfpBlob == null) return null;
        }
        try
        {
            var copy = (FWP_BYTE_BLOB*)mem.Alloc(sizeof(FWP_BYTE_BLOB));
            copy->size = wfpBlob->size;
            copy->data = (byte*)mem.Alloc((int)wfpBlob->size);
            Buffer.MemoryCopy(wfpBlob->data, copy->data, wfpBlob->size, wfpBlob->size);
            return copy;
        }
        finally
        {
            void* toFree = wfpBlob;
            Win.FwpmFreeMemory0(&toFree);
        }
    }

    // ------------------------------------------------------------------
    // Avisos de conexiones bloqueadas
    // ------------------------------------------------------------------

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static void OnNetEvent(void* context, FWPM_NET_EVENT1* e)
    {
        try { _current?.HandleNetEvent(e); }
        catch { /* nunca dejar que una excepción cruce a código nativo */ }
    }

    private void HandleNetEvent(FWPM_NET_EVENT1* e)
    {
        if (e == null || e->type != FWPM_NET_EVENT_TYPE.FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) return;
        var drop = e->Anonymous.classifyDrop;
        if (drop == null) return;
        bool ours = _filterInfo.TryGetValue(drop->filterId, out var filter);
        if (!ours)
        {
            // De otro filtro: solo interesan las entradas desde fuera (posibles ataques)
            if (drop->isLoopback || !IsInboundDrop(drop->msFwpDirection, drop->layerId)) return;
            filter = new FilterInfo("Firewall de Windows", false, true);
        }

        ref var h = ref e->header;
        string app = "";
        if ((h.flags & FLAG_APP_ID_SET) != 0 && h.appId.data != null && h.appId.size > 0)
        {
            string raw = new string((char*)h.appId.data, 0, (int)h.appId.size / 2).TrimEnd('\0');
            app = FileDetails.ProperCase(DevicePathToDosPath(raw));
        }

        IPAddress? remote = null;
        if ((h.flags & FLAG_REMOTE_ADDR_SET) != 0)
        {
            if (h.ipVersion == FWP_IP_VERSION.FWP_IP_VERSION_V4)
            {
                uint v = h.Anonymous2.remoteAddrV4;
                remote = new IPAddress(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });
            }
            else
            {
                var bytes = new byte[16];
                for (int i = 0; i < 16; i++) bytes[i] = h.Anonymous2.remoteAddrV6.byteArray16[i];
                remote = new IPAddress(bytes);
            }
        }

        string protocol = (h.flags & FLAG_IP_PROTOCOL_SET) == 0 ? "" : h.ipProtocol switch
        {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            58 => "ICMPv6",
            var p => "IP " + p
        };

        var c = new BlockedConnection
        {
            AppPath = app,
            Protocol = protocol,
            RemoteAddress = remote,
            RemotePort = (h.flags & FLAG_REMOTE_PORT_SET) != 0 ? h.remotePort : 0,
            LocalPort = (h.flags & FLAG_LOCAL_PORT_SET) != 0 ? h.localPort : 0,
            Inbound = filter!.Inbound,
            NeedsAnswer = filter.IsAskDefault,
            Reason = filter.Reason
        };
        if (!ours && IsBroadcastOrMulticast(ref h)) return; // avisos de aparatos de casa, no ataques
        if (ours) Blocked?.Invoke(c);
        else if (remote != null) ForeignInboundBlocked?.Invoke(c);
    }

    /// <summary>
    /// Desde Windows 10 (1903), los paquetes que llegan a puertos cerrados ("Port Scanning
    /// Prevention Filter") no se avisan salvo que se pida expresamente. Sin esto solo veíamos
    /// unos pocos intentos de cada escaneo. Se añade a lo que ya hubiera pedido otro programa.
    /// </summary>
    private void EnablePortScanEvents()
    {
        const uint PortScanningDrop = 0x20; // FWPM_NET_EVENT_KEYWORD_PORT_SCANNING_DROP
        uint current = 0;
        FWP_VALUE0* value = null;
        if (Win.FwpmEngineGetOption0(_engine, FWPM_ENGINE_OPTION.FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &value) == 0 && value != null)
        {
            if (value->type == FWP_DATA_TYPE.FWP_UINT32) current = value->Anonymous.uint32;
            Win.FwpmFreeMemory0((void**)&value);
        }
        if ((current & PortScanningDrop) != 0) return;
        var v = default(FWP_VALUE0);
        v.type = FWP_DATA_TYPE.FWP_UINT32;
        v.Anonymous.uint32 = current | PortScanningDrop;
        Win.FwpmEngineSetOption0(_engine, FWPM_ENGINE_OPTION.FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &v);
    }

    private static bool IsBroadcastOrMulticast(ref FWPM_NET_EVENT_HEADER1 h)
    {
        if ((h.flags & 0x2) == 0) return false; // FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET
        if (h.ipVersion == FWP_IP_VERSION.FWP_IP_VERSION_V4)
        {
            uint v = h.Anonymous1.localAddrV4;
            return (v >> 28) == 0xE || (v & 0xFF) == 0xFF; // 224.0.0.0/4 o x.x.x.255
        }
        return h.Anonymous1.localAddrV6.byteArray16[0] == 0xFF; // ff00::/8
    }

    /// <summary>
    /// ¿El paquete venía de fuera? Windows a veces da la dirección como 0/1 y otras como
    /// MS_FWP_DIRECTION_IN/OUT (0x3900/0x3901); por si acaso también se mira la capa.
    /// </summary>
    private static bool IsInboundDrop(uint direction, ushort layer)
    {
        if (direction is 1 or 0x3900) return true;
        if (direction is 0x3901) return false;
        // FWPS_LAYER_*: INBOUND_IPPACKET 0-3, INBOUND_TRANSPORT 12-15, INBOUND_ICMP_ERROR 28-31, ALE_AUTH_RECV_ACCEPT 44-47
        return layer is <= 3 or (>= 12 and <= 15) or (>= 28 and <= 31) or (>= 44 and <= 47);
    }

    // ------------------------------------------------------------------
    // Rutas: "\device\harddiskvolume3\..." → "C:\..."
    // ------------------------------------------------------------------

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int max);

    private void LoadDeviceMap()
    {
        _devices.Clear();
        foreach (var drive in DriveInfo.GetDrives())
        {
            string letter = drive.Name.TrimEnd('\\'); // "C:"
            var sb = new StringBuilder(512);
            if (QueryDosDevice(letter, sb, sb.Capacity) != 0)
                _devices.Add((sb.ToString(), letter));
        }
    }

    public string DevicePathToDosPath(string path)
    {
        foreach (var (device, drive) in _devices)
            if (path.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
                return drive + path[device.Length..];
        return path;
    }

    // ------------------------------------------------------------------

    private static void Check(uint result, string what)
    {
        if (result != 0)
            throw new InvalidOperationException($"No se pudo {what} (código 0x{result:X8}).");
    }

    public void Dispose()
    {
        if (_events != default) { Win.FwpmNetEventUnsubscribe0(_engine, _events); _events = default; }
        if (_engine != default) { Win.FwpmEngineClose0(_engine); _engine = default; } // borra los filtros dinámicos
        if (_current == this) _current = null;
    }

    /// <summary>Memoria nativa temporal que se libera al terminar de crear los filtros (WFP hace su propia copia).</summary>
    private sealed class Arena : IDisposable
    {
        private readonly List<IntPtr> _blocks = new();

        public void* Alloc(int size)
        {
            IntPtr p = Marshal.AllocHGlobal(Math.Max(1, size));
            _blocks.Add(p);
            return (void*)p;
        }

        public void Dispose()
        {
            foreach (var p in _blocks) Marshal.FreeHGlobal(p);
            _blocks.Clear();
        }
    }
}
