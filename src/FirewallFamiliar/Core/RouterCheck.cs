using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace FirewallFamiliar.Core;

/// <summary>Una puerta (puerto TCP) del router y lo que significa que esté abierta.</summary>
public sealed record RouterPort(int Port, string Service, string State, int Level, string Advice)
{
    public bool Open => State == "abierto";
    public string LevelText => !Open ? "" : Level switch { >= 3 => "⚠ Peligro", 2 => "Revisar", 1 => "Normal", _ => "Normal" };
}

/// <summary>Un puerto que un aparato de casa ha abierto en el router por UPnP (entra desde Internet hasta él).</summary>
public sealed record UpnpMapping(string Protocol, int ExternalPort, string InternalClient, int InternalPort,
    string Description, bool Enabled, int LeaseSeconds)
{
    public string Key => $"{Protocol}|{ExternalPort}|{InternalClient}|{InternalPort}";
    /// <summary>Programa de este PC que escucha en ese puerto (si el aparato es este PC).</summary>
    public string Program { get; set; } = "";
    public string Device { get; set; } = "";
    public string Text =>
        $"{Protocol} {ExternalPort} → {InternalClient}:{InternalPort}" +
        (Description.Length > 0 ? $" \"{Description}\"" : "") +
        (Device.Length > 0 ? $" ({Device})" : "") +
        (Program.Length > 0 ? $", programa {Program}" : "") +
        (!Enabled ? " (desactivado)" : "") +
        (LeaseSeconds > 0 ? $", caduca en {TimeSpan.FromSeconds(LeaseSeconds):h\\:mm}" : "");
}

/// <summary>Un aparato de la red de casa que este PC ha visto (tabla ARP).</summary>
public sealed record LanDevice(string Ip, string Mac, string Vendor, bool Randomized, bool IsGateway, bool IsThisPc)
{
    public string Kind => IsGateway ? "Router" : IsThisPc ? "Este PC" : Randomized ? "Dirección privada (móvil, tablet o PC)" : "";
    public string VendorText => Vendor.Length > 0 ? Vendor : Randomized ? "(oculto: dirección privada)" : "desconocido";
}

/// <summary>Resultado completo de la revisión del router.</summary>
public sealed class RouterReport
{
    public DateTime Time { get; init; } = DateTime.Now;
    public string Gateway { get; set; } = "";
    public string GatewayMac { get; set; } = "";
    public string RouterVendor { get; set; } = "";
    public string LocalIp { get; set; } = "";
    public string Adapter { get; set; } = "";
    public List<RouterPort> Ports { get; } = new();
    public bool RouterSilent { get; set; }
    /// <summary>null = no se ha mirado; true = el router contesta a UPnP.</summary>
    public bool? UpnpOn { get; set; }
    public string UpnpNote { get; set; } = "";
    public string RouterModel { get; set; } = "";
    public List<UpnpMapping> Mappings { get; } = new();
    public List<LanDevice> Devices { get; } = new();
    public string WifiSsid { get; set; } = "";
    public string WifiAuth { get; set; } = "";
    public string WifiCipher { get; set; } = "";
    public string WifiNote { get; set; } = "";
    public int WifiLevel { get; set; }
    public string Error { get; set; } = "";

    /// <summary>Clave de la red de casa: la MAC del router (un portátil fuera de casa ve otra red).</summary>
    public string NetworkKey => GatewayMac.Length > 0 ? GatewayMac : Gateway;
}

/// <summary>
/// Revisión del router desde dentro de casa (idea del programa Bastion, hecha a nuestra manera):
/// qué puertas del router contestan, qué puertos han abierto los aparatos por UPnP, qué aparatos
/// hay en la red y cómo está cifrado el Wi-Fi. TODO se queda en la red de casa: solo se habla con
/// el router y con los aparatos que contestan al aviso de UPnP. Nunca se prueba ninguna contraseña
/// ni se entra en el router.
/// </summary>
public static class RouterCheck
{
    private static readonly (int Port, string Service)[] GatewayPorts =
    {
        (21, "FTP (archivos sin cifrar)"),
        (22, "SSH (control remoto)"),
        (23, "Telnet (control remoto sin cifrar)"),
        (53, "DNS (nombres de webs)"),
        (80, "Página de configuración (sin cifrar)"),
        (139, "Disco compartido (NetBIOS)"),
        (443, "Página de configuración (cifrada)"),
        (445, "Disco compartido (SMB)"),
        (4567, "Gestión remota del operador (TR-069)"),
        (5000, "UPnP / servicio web"),
        (7547, "Gestión remota del operador (TR-069)"),
        (8080, "Página de configuración alternativa"),
        (8291, "Winbox (MikroTik)"),
        (8443, "Página de configuración alternativa (cifrada)"),
        (9000, "Servicio web"),
        (30005, "Gestión remota del operador (TR-069)"),
        (49152, "Control UPnP"),
        (52869, "Control UPnP (chip Realtek)"),
    };

    // ------------------------------------------------------------------ red de casa
    private static readonly string HomeFile = Path.Combine(RuleStore.Folder, "router-casa.txt");

    /// <summary>MAC del router de casa (null si aún no se ha visto ninguna red).</summary>
    public static string? HomeNetwork()
    {
        try { return File.Exists(HomeFile) ? File.ReadAllText(HomeFile).Trim() is { Length: > 0 } k ? k : null : null; }
        catch { return null; }
    }

    public static void SetHomeNetwork(string key)
    {
        try { Directory.CreateDirectory(RuleStore.Folder); File.WriteAllText(HomeFile, key); } catch { }
    }

    /// <summary>Router y red actual sin preguntar nada a nadie (solo la tabla ARP): para la medición diaria.</summary>
    public static (string Gateway, string NetworkKey) CurrentNetwork()
    {
        var r = new RouterReport();
        try { FindGateway(r); if (r.Gateway.Length > 0) ReadDevices(r); } catch { }
        return (r.Gateway, r.NetworkKey);
    }

    // ------------------------------------------------------------------ todo junto
    public static RouterReport Run(bool ports = true, CancellationToken cancel = default)
    {
        var r = new RouterReport();
        try
        {
            FindGateway(r);
            if (r.Gateway.Length == 0) { r.Error = "No se ha encontrado el router (¿sin conexión?)."; ReadWifi(r); return r; }
            // El aviso de UPnP va primero: los aparatos que contestan entran en la tabla ARP
            try { ReadUpnp(r, cancel); } catch (Exception ex) { r.UpnpNote = "No se pudo mirar UPnP: " + ex.Message; }
            if (ports) try { ProbePorts(r, cancel); } catch { }
            try { ReadDevices(r); } catch { }
            ReadWifi(r);
            NameMappings(r);
        }
        catch (Exception ex) { r.Error = ex.Message; }
        return r;
    }

    // ------------------------------------------------------------------ router
    private static readonly string[] VirtualWords =
        { "vpn", "wireguard", "tap-", "tailscale", "proton", "wintun", "openvpn", "virtual", "hyper-v", "vmware", "virtualbox", "zerotier" };

    private static void FindGateway(RouterReport r)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.OperationalStatus == OperationalStatus.Up)
                     .OrderBy(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 1 : 0))
        {
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp) continue;
            string desc = (nic.Description + " " + nic.Name).ToLowerInvariant();
            if (VirtualWords.Any(w => desc.Contains(w))) continue;
            var props = nic.GetIPProperties();
            var gw = props.GatewayAddresses.Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            if (gw == null || !IsPrivate(gw)) continue;
            var me = props.UnicastAddresses.FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);
            r.Gateway = gw.ToString();
            r.LocalIp = me?.Address.ToString() ?? "";
            r.Adapter = nic.Name;
            return;
        }
    }

    private static bool IsPrivate(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168);
    }

    // ------------------------------------------------------------------ puertas del router
    private static void ProbePorts(RouterReport r, CancellationToken cancel)
    {
        var gw = IPAddress.Parse(r.Gateway);
        var tasks = GatewayPorts.Select(p => Task.Run(() => (p, Probe(gw, p.Port, cancel)))).ToArray();
        Task.WaitAll(tasks, cancel);
        var results = tasks.Select(t => t.Result).OrderBy(x => x.p.Port).ToList();
        bool httpsOpen = results.Any(x => x.p.Port is 443 or 8443 && x.Item2 == "abierto");
        foreach (var (p, state) in results)
        {
            var (level, advice) = Explain(p.Port, httpsOpen);
            r.Ports.Add(new RouterPort(p.Port, p.Service, state, level, advice));
        }
        r.RouterSilent = r.Ports.All(p => p.State == "sin respuesta");
    }

    private static string Probe(IPAddress ip, int port, CancellationToken cancel)
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            var t = s.ConnectAsync(new IPEndPoint(ip, port), cancel).AsTask();
            if (!t.Wait(1500, cancel)) return "sin respuesta";
            return "abierto";
        }
        catch (AggregateException ae) when (ae.InnerException is SocketException se) { return se.SocketErrorCode == SocketError.ConnectionRefused ? "cerrado" : "sin respuesta"; }
        catch (SocketException se) { return se.SocketErrorCode == SocketError.ConnectionRefused ? "cerrado" : "sin respuesta"; }
        catch { return "sin respuesta"; }
    }

    private static (int Level, string Advice) Explain(int port, bool httpsOpen) => port switch
    {
        23 => (3, "Telnet deja manejar el router sin cifrar. Apágalo en la configuración del router (Administración / Telnet) o pide al operador que lo quite."),
        22 => (2, "SSH permite manejar el router a distancia. En casa no hace falta: si no lo has activado tú, apágalo."),
        21 => (2, "El router comparte archivos (un disco USB) por FTP sin cifrar. Si no lo usas, apágalo."),
        139 or 445 => (2, "El router comparte un disco o USB con la red. Si no lo usas, apágalo; si lo usas, que tenga contraseña."),
        8291 => (2, "Winbox es el programa para manejar routers MikroTik. Si no es tu router, revisa quién lo ha puesto."),
        80 => httpsOpen
            ? (1, "La página de configuración también contesta sin cifrar. Entra siempre por https.")
            : (2, "La página de configuración solo va sin cifrar: la contraseña del router viaja tal cual por la red de casa. Que sea larga y no la escribas desde un Wi-Fi de invitados."),
        7547 or 4567 or 30005 => (1, "Es el puerto que usa el operador (Vodafone, Movistar...) para actualizar y configurar el router a distancia. En los routers del operador es normal y no se puede cerrar desde casa."),
        8080 or 8443 or 9000 => (1, "Otra página web del router (configuración o servicios). Normal en muchos routers."),
        53 => (0, "El router responde a las consultas de nombres de webs. Normal."),
        443 => (0, "Página de configuración cifrada. Bien."),
        5000 or 49152 or 52869 => (0, "Parte de UPnP (abajo se explica)."),
        _ => (0, "")
    };

    // ------------------------------------------------------------------ UPnP
    private static readonly HttpClient Http = new(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
    { Timeout = TimeSpan.FromSeconds(4) };

    private static void ReadUpnp(RouterReport r, CancellationToken cancel)
    {
        var gw = IPAddress.Parse(r.Gateway);
        var locations = new List<string>();
        using (var udp = new UdpClient(new IPEndPoint(r.LocalIp.Length > 0 ? IPAddress.Parse(r.LocalIp) : IPAddress.Any, 0)))
        {
            udp.Client.ReceiveTimeout = 500;
            var target = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
            foreach (string st in new[] { "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2", "ssdp:all" })
            {
                byte[] msg = Encoding.ASCII.GetBytes($"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n");
                udp.Send(msg, msg.Length, target);
            }
            var end = DateTime.UtcNow.AddSeconds(3);
            while (DateTime.UtcNow < end && !cancel.IsCancellationRequested)
            {
                try
                {
                    var from = new IPEndPoint(IPAddress.Any, 0);
                    string text = Encoding.ASCII.GetString(udp.Receive(ref from));
                    if (!from.Address.Equals(gw)) continue; // los demás aparatos solo sirven para llenar la tabla ARP
                    var m = Regex.Match(text, @"^LOCATION:\s*(\S+)", RegexOptions.IgnoreCase | RegexOptions.Multiline);
                    if (m.Success && !locations.Contains(m.Groups[1].Value)) locations.Add(m.Groups[1].Value);
                }
                catch (SocketException) { }
            }
        }
        if (locations.Count == 0)
        {
            r.UpnpOn = false;
            r.UpnpNote = "El router no contesta a UPnP: los programas de casa no pueden abrir puertos solos. Bien.";
            return;
        }
        r.UpnpOn = true;
        foreach (string loc in locations)
        {
            // Solo se habla con el propio router: si la dirección apunta a otro sitio, se ignora
            if (!Uri.TryCreate(loc, UriKind.Absolute, out var uri) || uri.Scheme != "http" || uri.Host != r.Gateway) continue;
            XDocument doc;
            try { doc = XDocument.Parse(Http.GetStringAsync(uri, cancel).GetAwaiter().GetResult()); }
            catch { continue; }
            if (r.RouterModel.Length == 0)
            {
                var dev = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
                string Field(string n) => dev?.Elements().FirstOrDefault(e => e.Name.LocalName == n)?.Value.Trim() ?? "";
                r.RouterModel = string.Join(" ", new[] { Field("manufacturer"), Field("modelName"), Field("modelNumber") }.Where(s => s.Length > 0).Distinct());
            }
            foreach (var svc in doc.Descendants().Where(e => e.Name.LocalName == "service"))
            {
                string type = svc.Elements().FirstOrDefault(e => e.Name.LocalName == "serviceType")?.Value.Trim() ?? "";
                string control = svc.Elements().FirstOrDefault(e => e.Name.LocalName == "controlURL")?.Value.Trim() ?? "";
                if (!(type.Contains(":WANIPConnection:") || type.Contains(":WANPPPConnection:")) || control.Length == 0) continue;
                if (!Uri.TryCreate(uri, control, out var ctl) || ctl.Host != r.Gateway) continue;
                ReadMappings(r, ctl, type, cancel);
            }
        }
        r.UpnpNote = r.Mappings.Count == 0
            ? "UPnP está encendido en el router, pero ahora no hay puertos abiertos por él."
            : $"UPnP está encendido: hay {r.Mappings.Count} puerto(s) abiertos desde Internet hacia aparatos de casa.";
    }

    private static void ReadMappings(RouterReport r, Uri control, string type, CancellationToken cancel)
    {
        for (int i = 0; i < 128 && !cancel.IsCancellationRequested; i++)
        {
            string body =
                "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>" +
                $"<u:GetGenericPortMappingEntry xmlns:u=\"{type}\"><NewPortMappingIndex>{i}</NewPortMappingIndex></u:GetGenericPortMappingEntry>" +
                "</s:Body></s:Envelope>";
            using var req = new HttpRequestMessage(HttpMethod.Post, control) { Content = new StringContent(body, Encoding.UTF8, "text/xml") };
            req.Headers.TryAddWithoutValidation("SOAPAction", $"\"{type}#GetGenericPortMappingEntry\"");
            HttpResponseMessage res;
            try { res = Http.Send(req, cancel); } catch { return; }
            using (res)
            {
                if (!res.IsSuccessStatusCode) return; // fin de la lista (error 713) o el router no lo deja
                XDocument doc;
                try { doc = XDocument.Parse(res.Content.ReadAsStringAsync(cancel).GetAwaiter().GetResult()); } catch { return; }
                string F(string n) => doc.Descendants().FirstOrDefault(e => e.Name.LocalName == n)?.Value.Trim() ?? "";
                int.TryParse(F("NewExternalPort"), out int ext);
                int.TryParse(F("NewInternalPort"), out int intPort);
                int.TryParse(F("NewLeaseDuration"), out int lease);
                if (ext == 0 && intPort == 0) return;
                var m = new UpnpMapping(F("NewProtocol").ToUpperInvariant(), ext, F("NewInternalClient"), intPort,
                    F("NewPortMappingDescription"), F("NewEnabled") is "1" or "true", lease);
                if (!r.Mappings.Any(x => x.Key == m.Key)) r.Mappings.Add(m);
            }
        }
    }

    /// <summary>Pone a cada puerto abierto el nombre del aparato y, si es este PC, el programa que escucha.</summary>
    private static void NameMappings(RouterReport r)
    {
        List<ConnectionInfo>? conns = null;
        foreach (var m in r.Mappings)
        {
            var dev = r.Devices.FirstOrDefault(d => d.Ip == m.InternalClient);
            if (m.InternalClient == r.LocalIp) m.Device = "este PC";
            else if (dev != null) m.Device = dev.Vendor.Length > 0 ? dev.Vendor : dev.Kind;
            if (m.InternalClient != r.LocalIp) continue;
            conns ??= ConnectionMonitor.GetAll();
            var c = conns.FirstOrDefault(x => x.LocalPort == m.InternalPort && (m.Protocol == "UDP" ? x.Protocol.StartsWith("UDP") : x.IsListening));
            if (c == null) continue;
            string? path = c.Pid == 4 ? "System" : NativeMethods.GetProcessPath(c.Pid);
            if (!string.IsNullOrEmpty(path)) m.Program = path;
        }
    }

    // ------------------------------------------------------------------ aparatos de casa (tabla ARP)
    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow
    {
        public int Index;
        public int PhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] PhysAddr;
        public uint Addr;
        public int Type; // 2 = no válida, 3 = dinámica, 4 = fija
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable(IntPtr table, ref int size, bool order);

    private static void ReadDevices(RouterReport r)
    {
        var me = r.LocalIp.Length > 0 ? IPAddress.Parse(r.LocalIp) : null;
        var gw = IPAddress.Parse(r.Gateway);
        int size = 0;
        GetIpNetTable(IntPtr.Zero, ref size, true);
        if (size <= 0) return;
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buf, ref size, true) != 0) return;
            int n = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MibIpNetRow>();
            var seen = new HashSet<string>();
            for (int i = 0; i < n; i++)
            {
                var row = Marshal.PtrToStructure<MibIpNetRow>(buf + 4 + i * rowSize);
                if (row.Type == 2 || row.PhysAddrLen != 6) continue;
                var ip = new IPAddress(row.Addr);
                byte[] b = ip.GetAddressBytes();
                if (b[0] >= 224 || b[3] == 255 || b[3] == 0) continue;
                if (!SameNet(ip, gw)) continue;
                var mac = row.PhysAddr.Take(6).ToArray();
                if (mac.All(x => x == 0) || mac.All(x => x == 0xFF) || (mac[0] & 1) == 1) continue;
                string macText = string.Join("-", mac.Select(x => x.ToString("X2")));
                if (!seen.Add(ip + macText)) continue;
                bool random = (mac[0] & 2) == 2;
                bool isGw = ip.Equals(gw);
                r.Devices.Add(new LanDevice(ip.ToString(), macText, random ? "" : Vendor(macText), random, isGw, ip.Equals(me)));
                if (isGw) { r.GatewayMac = macText; r.RouterVendor = random ? "" : Vendor(macText); }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        // Este PC no sale en su propia tabla ARP
        if (me != null && !r.Devices.Any(d => d.IsThisPc))
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(x => x.Name == r.Adapter);
            var mac = nic?.GetPhysicalAddress().GetAddressBytes();
            if (mac is { Length: 6 })
            {
                string macText = string.Join("-", mac.Select(x => x.ToString("X2")));
                bool random = (mac[0] & 2) == 2;
                r.Devices.Add(new LanDevice(me.ToString(), macText, random ? "" : Vendor(macText), random, false, true));
            }
        }
        r.Devices.Sort((a, b) => IpOrder(a.Ip).CompareTo(IpOrder(b.Ip)));
    }

    private static uint IpOrder(string ip)
    {
        var b = IPAddress.Parse(ip).GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    /// <summary>Misma red de casa: los tres primeros números iguales (las redes de casa son /24).</summary>
    private static bool SameNet(IPAddress a, IPAddress b)
    {
        var x = a.GetAddressBytes(); var y = b.GetAddressBytes();
        return x[0] == y[0] && x[1] == y[1] && x[2] == y[2];
    }

    // ------------------------------------------------------------------ fabricantes (lista del IEEE dentro del programa)
    private static Dictionary<string, string>? _vendors;
    private static readonly object VendorLock = new();

    public static string Vendor(string mac)
    {
        string key = new string(mac.Where(Uri.IsHexDigit).Take(6).ToArray()).ToUpperInvariant();
        if (key.Length < 6) return "";
        lock (VendorLock)
        {
            if (_vendors == null)
            {
                _vendors = new Dictionary<string, string>();
                try
                {
                    using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("FirewallFamiliar.fabricantes.txt");
                    if (s != null)
                    {
                        using var rd = new StreamReader(s);
                        string? line;
                        while ((line = rd.ReadLine()) != null)
                        {
                            if (line.Length < 8 || line[0] == '#') continue;
                            int tab = line.IndexOf('\t');
                            if (tab == 6) _vendors[line[..6]] = line[7..];
                        }
                    }
                }
                catch { }
            }
            return _vendors.TryGetValue(key, out var v) ? v : "";
        }
    }

    // ------------------------------------------------------------------ Wi-Fi
    private static void ReadWifi(RouterReport r)
    {
        string text;
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var psi = new ProcessStartInfo("netsh", "wlan show interfaces")
            {
                UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true,
                StandardOutputEncoding = Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage)
            };
            using var p = Process.Start(psi)!;
            text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
        }
        catch { r.WifiNote = "No se pudo leer el Wi-Fi."; return; }

        string Value(params string[] keys)
        {
            foreach (var line in text.Split('\n'))
            {
                int colon = line.IndexOf(':');
                if (colon < 0) continue;
                string k = line[..colon].Trim();
                if (keys.Any(x => k.Equals(x, StringComparison.OrdinalIgnoreCase))) return line[(colon + 1)..].Trim();
            }
            return "";
        }
        r.WifiSsid = Value("SSID");
        r.WifiAuth = Value("Autenticación", "Authentication", "Autenticacion");
        r.WifiCipher = Value("Cifrado", "Cipher");
        if (r.WifiAuth.Length == 0)
        {
            r.WifiNote = text.Contains("ubicación", StringComparison.OrdinalIgnoreCase) || text.Contains("location", StringComparison.OrdinalIgnoreCase)
                ? "Windows no deja leer el Wi-Fi sin permiso de ubicación (Configuración > Privacidad > Ubicación)."
                : "Este PC no está conectado por Wi-Fi (o va por cable).";
            return;
        }
        string a = r.WifiAuth.ToUpperInvariant();
        string c = r.WifiCipher.ToUpperInvariant();
        if (a.Contains("WEP") || c.Contains("WEP") || a.StartsWith("ABIERT") || a.StartsWith("OPEN") || c is "NINGUNO" or "NONE")
        { r.WifiLevel = 3; r.WifiNote = "El Wi-Fi va SIN cifrar o con WEP (se descifra en minutos). Pon WPA2 o WPA3 en el router y una contraseña nueva."; }
        else if (!a.Contains("WPA2") && !a.Contains("WPA3"))
        { r.WifiLevel = 2; r.WifiNote = "El Wi-Fi usa WPA antiguo. Cámbialo a WPA2 (AES) o WPA3 en el router."; }
        else if (c.Contains("TKIP"))
        { r.WifiLevel = 2; r.WifiNote = "El cifrado TKIP es antiguo. Ponlo en AES (CCMP) en el router."; }
        else
        { r.WifiLevel = 0; r.WifiNote = a.Contains("WPA3") ? "WPA3: lo más seguro." : "WPA2 con AES: bien."; }
    }

    // ------------------------------------------------------------------ texto para el informe
    public static string Section(RouterReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## 11. Router y red de casa");
        sb.AppendLine();
        string? homeKey = HomeNetwork();
        if (r.NetworkKey.Length > 0 && homeKey != null && homeKey != r.NetworkKey)
        {
            sb.AppendLine("**Este PC NO está ahora en la red de casa** (oficina u otro sitio): fuera de casa solo se avisa de lo crítico para este PC.");
            sb.AppendLine();
        }
        sb.AppendLine($"Revisión hecha desde este PC ({r.Time:dd/MM/yyyy HH:mm}), sin salir de casa: solo se habla con el router. " +
                      "No se prueba ninguna contraseña. Lo que se ve desde dentro no demuestra qué se ve desde Internet.");
        sb.AppendLine();
        if (r.Error.Length > 0) { sb.AppendLine("- " + r.Error); sb.AppendLine(); }
        if (r.Gateway.Length > 0)
            sb.AppendLine($"- Router: {r.Gateway}{(r.RouterModel.Length > 0 ? $", {r.RouterModel}" : r.RouterVendor.Length > 0 ? $", {r.RouterVendor}" : "")}" +
                          $"{(r.GatewayMac.Length > 0 ? $" (MAC {r.GatewayMac})" : "")}. Este PC: {r.LocalIp} por \"{r.Adapter}\".");
        if (r.WifiSsid.Length > 0 || r.WifiNote.Length > 0)
            sb.AppendLine($"- Wi-Fi{(r.WifiSsid.Length > 0 ? $" \"{r.WifiSsid}\"" : "")}: {(r.WifiAuth.Length > 0 ? $"{r.WifiAuth} / {r.WifiCipher}. " : "")}{(r.WifiLevel >= 2 ? "⚠ " : "")}{r.WifiNote}");
        if (r.UpnpOn != null) sb.AppendLine($"- UPnP: {(r.UpnpOn == true ? "⚠ " : "✔ ")}{r.UpnpNote}");
        sb.AppendLine();

        if (r.Ports.Count > 0)
        {
            var open = r.Ports.Where(p => p.Open).ToList();
            sb.AppendLine($"### Puertas del router que contestan ({open.Count} de {r.Ports.Count} probadas)");
            sb.AppendLine();
            if (r.RouterSilent) sb.AppendLine("El router no ha contestado a nada (una VPN o un Wi-Fi de invitados lo tapan): no se sabe qué tiene abierto.");
            else if (open.Count == 0) sb.AppendLine("Ninguna.");
            foreach (var p in open.OrderByDescending(p => p.Level).ThenBy(p => p.Port))
                sb.AppendLine($"- {(p.Level >= 2 ? "⚠ " : "")}{p.Port} {p.Service}: {p.Advice}");
            sb.AppendLine();
        }

        if (r.Mappings.Count > 0)
        {
            sb.AppendLine($"### Puertos abiertos en el router por UPnP ({r.Mappings.Count})");
            sb.AppendLine();
            sb.AppendLine("Cada línea es una puerta abierta desde Internet hasta un aparato de casa, puesta por un programa sin preguntar.");
            sb.AppendLine();
            foreach (var m in r.Mappings) sb.AppendLine("- " + m.Text);
            sb.AppendLine();
        }

        var speeds = SpeedHistory.Load().Where(s => s.Time > DateTime.Now.AddDays(-14)).ToList();
        sb.AppendLine($"### Mediciones de velocidad (últimos 14 días: {speeds.Count}, {speeds.Count(s => s.Bad)} con problemas)");
        sb.AppendLine();
        if (speeds.Count == 0) sb.AppendLine("Ninguna todavía (se mide una vez al día cuando el PC está en casa).");
        else
        {
            sb.AppendLine("| Cuándo | Bajada | Subida | Latencia | Línea llena ↓/↑ | Router | Estado |");
            sb.AppendLine("|---|---|---|---|---|---|---|");
            foreach (var s in speeds)
                sb.AppendLine($"| {s.TimeText} | {s.DownText} | {s.UpText} | {s.PingText} | {s.LoadedText} | {s.RouterText} | {s.StateText.Replace("|", "/")} |");
        }
        sb.AppendLine();

        if (r.Devices.Count > 0)
        {
            sb.AppendLine($"### Aparatos que este PC ve en la red ({r.Devices.Count})");
            sb.AppendLine();
            sb.AppendLine("Solo salen los que han hablado hace poco con este PC (o han contestado al aviso de UPnP); puede haber más.");
            sb.AppendLine();
            sb.AppendLine("| IP | MAC | Fabricante | Qué es |");
            sb.AppendLine("|---|---|---|---|");
            foreach (var d in r.Devices) sb.AppendLine($"| {d.Ip} | {d.Mac} | {d.VendorText.Replace("|", "/")} | {d.Kind} |");
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
