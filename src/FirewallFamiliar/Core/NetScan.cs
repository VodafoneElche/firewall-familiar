using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace FirewallFamiliar.Core;

/// <summary>Grupo del árbol de aparatos (como las carpetas de un programa de vigilancia de red).</summary>
public enum DeviceGroup { Router, Ordenadores, Moviles, TeleConsolas, Impresoras, Otros, Desconocidos }

/// <summary>Color del cuadrito de cada aparato.</summary>
public enum DeviceState { DeCasa, SinNombre, Revisar, NoResponde }

/// <summary>Un aparato encontrado al escanear la red de casa, con todo lo que se ha podido averiguar.</summary>
public sealed class ScanDevice
{
    public string Ip { get; set; } = "";
    public string Mac { get; set; } = "";
    public string Vendor { get; set; } = "";
    public bool Randomized { get; set; }
    public bool IsGateway { get; set; }
    public bool IsThisPc { get; set; }
    public bool Answered { get; set; } = true;
    public int Ttl { get; set; }
    public long PingMs { get; set; } = -1;
    public string NetbiosName { get; set; } = "";
    public string Workgroup { get; set; } = "";
    public string MdnsName { get; set; } = "";
    public string LlmnrName { get; set; } = "";
    /// <summary>Nombre que dijo al conectarse al Wi-Fi (el mismo que sale en la página del router).</summary>
    public string DhcpName { get; set; } = "";
    public string DhcpVendor { get; set; } = "";
    public string DnsName { get; set; } = "";
    public string SsdpName { get; set; } = "";
    public string SsdpModel { get; set; } = "";
    /// <summary>Nombre que dio en otro escaneo (si esta vez no lo dice).</summary>
    public string OldName { get; set; } = "";
    public List<string> Services { get; set; } = new();
    public List<int> OpenPorts { get; set; } = new();
    public DeviceGroup Group { get; set; } = DeviceGroup.Desconocidos;
    public string TypeText { get; set; } = "";
    // Lo que ha puesto Jose (aparatos.json)
    public string Label { get; set; } = "";
    public bool Home { get; set; }
    /// <summary>Escaneado en una red que no es la de casa (cliente, oficina): no se guarda nada.</summary>
    public bool Away { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }

    /// <summary>Mejor nombre encontrado en la red (sin contar el que pone Jose).</summary>
    public string HostName =>
        new[] { DhcpName, MdnsName, NetbiosName, LlmnrName, DnsName, SsdpName, OldName }.FirstOrDefault(s => s.Length > 0) ?? "";

    public string DisplayName =>
        Label.Length > 0 ? Label :
        IsThisPc ? $"Este PC{(HostName.Length > 0 ? $" ({HostName})" : "")}" :
        HostName.Length > 0 ? HostName :
        TypeShort.Length > 0 && Vendor.Length > 0 ? $"{TypeShort} {ShortVendor}" :
        TypeShort.Length > 0 ? TypeShort :
        Vendor.Length > 0 ? ShortVendor : "Aparato desconocido";

    private string TypeShort => Regex.Replace(TypeText, @"\s*\(.*\)$", "");

    public string ShortVendor
    {
        get
        {
            string v = Regex.Replace(Vendor, @"[,.]?\s*(Co\.?,?\s*Ltd\.?|Inc\.?|Corporation|Corp\.?|Limited|GmbH|S\.?A\.?|LLC|Technologies|Technology|Electronics|International|Communication(s)?)\b.*$", "", RegexOptions.IgnoreCase).Trim(' ', ',', '.');
            return v.Length > 0 ? v : Vendor;
        }
    }

    public string VendorText => Vendor.Length > 0 ? Vendor : Randomized ? "(oculto: dirección privada del móvil o PC)" : "desconocido";

    public bool DangerousPort => OpenPorts.Any(p => NetScan.PortLevel(p) >= 3);

    public DeviceState State =>
        !Answered ? DeviceState.NoResponde :
        DangerousPort ? DeviceState.Revisar :
        Home || IsGateway || IsThisPc ? DeviceState.DeCasa :
        Group == DeviceGroup.Desconocidos ? DeviceState.Revisar : DeviceState.SinNombre;

    public string StateColor => State switch
    {
        DeviceState.DeCasa => "#2E9E44",
        DeviceState.SinNombre => "#A0A4AA",
        DeviceState.Revisar => "#F08C00",
        _ => "#D32F2F"
    };

    public string StateText => State switch
    {
        DeviceState.DeCasa => Away ? "Contesta (red fuera de casa: no se guarda nada)." : "De casa: conocido y contesta.",
        DeviceState.SinNombre => "Contesta, pero aún no le has puesto nombre ni lo has marcado como de casa.",
        DeviceState.Revisar => DangerousPort ? "⚠ Tiene una puerta peligrosa abierta (mira abajo)." : "No se sabe qué es: conviene averiguarlo.",
        _ => "No ha contestado en este escaneo (apagado, fuera de casa o dormido)."
    };

    public string IpText => Answered ? Ip : $"{Ip} (antes)";

    public string NamesText
    {
        get
        {
            var parts = new List<string>();
            if (DhcpName.Length > 0) parts.Add($"{DhcpName} (lo dijo al conectarse; es el nombre que sale en el router)");
            if (MdnsName.Length > 0) parts.Add($"{MdnsName} (Bonjour/mDNS)");
            if (NetbiosName.Length > 0) parts.Add($"{NetbiosName}{(Workgroup.Length > 0 ? $" en el grupo {Workgroup}" : "")} (red de Windows)");
            if (LlmnrName.Length > 0 && LlmnrName != NetbiosName) parts.Add($"{LlmnrName} (Windows, LLMNR)");
            if (DnsName.Length > 0) parts.Add($"{DnsName} (router)");
            if (SsdpName.Length > 0) parts.Add($"{SsdpName}{(SsdpModel.Length > 0 && SsdpModel != SsdpName ? $" – {SsdpModel}" : "")} (UPnP)");
            else if (SsdpModel.Length > 0) parts.Add($"{SsdpModel} (UPnP)");
            if (parts.Count == 0 && OldName.Length > 0) parts.Add($"{OldName} (lo dijo en otro escaneo)");
            return parts.Count > 0 ? string.Join("\n", parts) : "No dice su nombre a la red.";
        }
    }

    public string PortsText => OpenPorts.Count == 0
        ? (Answered ? "Ninguna de las que se prueban." : "")
        : string.Join("\n", OpenPorts.Select(p => $"{(NetScan.PortLevel(p) >= 3 ? "⚠ " : NetScan.PortLevel(p) == 2 ? "· " : "")}{p} – {NetScan.PortName(p)}"));

    /// <summary>Qué es esta MAC, explicado: fabricante y qué suele fabricar, o por qué no se sabe.</summary>
    public string MacText => NetScan.ExplainMac(this);

    public string TypeDisplay => TypeText.Length > 0 ? TypeText : "No se sabe.";

    public string ServicesText { get { lock (Services) return Services.Count == 0 ? "No anuncia ninguno." : string.Join(", ", Services.Select(NetScan.ServiceName).Distinct()); } }

    public string PingText => !Answered ? "—" : PingMs < 0 ? "no contesta al ping (normal en móviles y PCs con cortafuegos)" :
        $"{PingMs} ms{(Ttl > 0 ? $" (TTL {Ttl}: {NetScan.TtlHint(Ttl)})" : "")}";

    public string SeenText => FirstSeen == default ? "" :
        $"Primera vez: {FirstSeen:dd/MM/yyyy HH:mm}. Última: {LastSeen:dd/MM/yyyy HH:mm}.";

    public string Tooltip => $"{DisplayName}\n{Ip}  {Mac}\n{StateText}";
}

/// <summary>
/// Escaneo de la red de casa, al estilo del "descubrimiento" de los programas de vigilancia de red
/// (PRTG y parecidos), hecho a nuestra manera y sin salir de casa:
///  1. se pregunta por ARP a las 254 direcciones de la red, para encontrar todo lo encendido;
///  2. a cada aparato se le pide su nombre por tres vías que usan los propios aparatos de casa
///     (red de Windows/NetBIOS, Bonjour/mDNS y al router por DNS) y por UPnP su modelo;
///  3. se prueban unas pocas puertas (puertos TCP) para saber qué tipo de aparato es y si tiene
///     algo peligroso abierto. Nunca se prueba una contraseña ni se entra en ningún aparato.
/// </summary>
public static class NetScan
{
    private static readonly (int Port, string Name, int Level)[] Ports =
    {
        (21, "FTP: archivos sin cifrar", 2),
        (22, "SSH: control remoto", 2),
        (23, "Telnet: control remoto SIN cifrar", 3),
        (53, "DNS", 0),
        (80, "Página web (configuración)", 0),
        (139, "Carpetas compartidas de Windows (antiguo)", 1),
        (443, "Página web cifrada", 0),
        (445, "Carpetas compartidas de Windows", 1),
        (515, "Impresora (LPD)", 0),
        (554, "Vídeo en directo (cámara, RTSP)", 1),
        (631, "Impresora (IPP)", 0),
        (1883, "Domótica (MQTT)", 1),
        (3389, "Escritorio remoto de Windows", 2),
        (5000, "Servicio web / NAS", 0),
        (5555, "Depuración de Android ABIERTA: control total del móvil o tele", 3),
        (5900, "VNC: control remoto de pantalla", 2),
        (7000, "AirPlay (Apple)", 0),
        (8008, "Chromecast / Google TV", 0),
        (8009, "Chromecast / Google TV", 0),
        (8080, "Página web alternativa", 0),
        (8443, "Página web alternativa cifrada", 0),
        (9100, "Impresora (impresión directa)", 0),
        (9295, "PlayStation (juego remoto)", 0),
        (62078, "iPhone / iPad (sincronización)", 0),
    };

    public static int PortLevel(int port) => Ports.FirstOrDefault(p => p.Port == port).Level;
    public static string PortName(int port) => Ports.FirstOrDefault(p => p.Port == port).Name ?? "";

    public static string TtlHint(int ttl) => ttl switch
    {
        > 128 => "aparato de red",
        > 64 => "Windows",
        _ => "móvil, Mac, Linux o aparato"
    };

    public static string ServiceName(string s)
    {
        string k = s.ToLowerInvariant();
        if (k.StartsWith("upnp:")) return s[5..];
        return k switch
        {
            _ when k.StartsWith("_googlecast") => "Chromecast",
            _ when k.StartsWith("_airplay") || k.StartsWith("_raop") => "AirPlay",
            _ when k.StartsWith("_companion-link") => "Apple",
            _ when k.StartsWith("_ipp") || k.StartsWith("_printer") || k.StartsWith("_pdl-datastream") => "impresora",
            _ when k.StartsWith("_hap") || k.StartsWith("_homekit") => "HomeKit",
            _ when k.StartsWith("_spotify-connect") => "Spotify Connect",
            _ when k.StartsWith("_smb") => "carpetas compartidas",
            _ when k.StartsWith("_sleep-proxy") => "Apple TV/HomePod",
            _ when k.StartsWith("_amzn") => "Amazon",
            _ => s.Split('.')[0].TrimStart('_')
        };
    }

    // ------------------------------------------------------------------ 1. ARP a toda la red
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physAddrLen);

    /// <summary>
    /// Pregunta por ARP a las 254 direcciones de la red del router (/24, como todas las redes de casa).
    /// Los aparatos que contestan quedan además en la tabla ARP de Windows. Tarda unos segundos.
    /// </summary>
    /// <summary>
    /// Las preguntas a los aparatos esperan respuesta (bloquean un hilo). Sin esto, Windows da los
    /// hilos de uno en uno y el escaneo tardaba casi un minuto en vez de unos 15 segundos.
    /// </summary>
    private static void EnoughThreads()
    {
        ThreadPool.GetMinThreads(out int w, out int io);
        if (w < 160) ThreadPool.SetMinThreads(160, Math.Max(io, 32));
    }

    public static List<(string Ip, string Mac)> Sweep(string gateway, CancellationToken cancel = default)
    {
        EnoughThreads();
        var found = new ConcurrentBag<(string, string)>();
        if (!IPAddress.TryParse(gateway, out var gw)) return new();
        byte[] b = gw.GetAddressBytes();
        try
        {
            Parallel.For(1, 255, new ParallelOptions { MaxDegreeOfParallelism = 64, CancellationToken = cancel }, i =>
            {
                var ip = new IPAddress(new[] { b[0], b[1], b[2], (byte)i });
                byte[] mac = new byte[6];
                int len = 6;
                try
                {
                    if (SendARP(BitConverter.ToUInt32(ip.GetAddressBytes(), 0), 0, mac, ref len) != 0 || len != 6) return;
                }
                catch { return; }
                if (mac.All(x => x == 0) || (mac[0] & 1) == 1) return;
                found.Add((ip.ToString(), string.Join("-", mac.Select(x => x.ToString("X2")))));
            });
        }
        catch (OperationCanceledException) { }
        return found.OrderBy(x => IpOrder(x.Item1)).ToList();
    }

    // ------------------------------------------------------------------ escaneo completo (ventana)
    public static List<ScanDevice> Run(RouterReport r, IProgress<string>? progress, CancellationToken cancel)
    {
        progress?.Report("Buscando aparatos en las 254 direcciones de casa...");
        var arp = Sweep(r.Gateway, cancel);
        var devices = new List<ScanDevice>();
        foreach (var (ip, mac) in arp)
            devices.Add(NewDevice(ip, mac, r));
        // Lo que ya estaba en la tabla ARP o ha contestado a UPnP en la revisión del router
        // Una sola entrada por IP (algunos routers, como los ZTE, contestan con dos MAC)
        devices = devices.GroupBy(d => d.Ip).Select(g => g.First()).ToList();
        foreach (var d in r.Devices.Where(d => !devices.Any(x => x.Mac == d.Mac || x.Ip == d.Ip)))
            devices.Add(NewDevice(d.Ip, d.Mac, r));
        if (r.LocalIp.Length > 0 && !devices.Any(d => d.IsThisPc))
        {
            var me = r.Devices.FirstOrDefault(d => d.IsThisPc);
            if (me != null) devices.Add(NewDevice(me.Ip, me.Mac, r));
        }
        cancel.ThrowIfCancellationRequested();

        AddDhcp(devices);
        progress?.Report($"Encontrados {devices.Count} aparatos. Preguntando su nombre y qué son...");
        var ssdp = ReadSsdp(r.LocalIp, cancel);
        var others = devices.Where(d => !d.IsThisPc).ToList();
        var tasks = new List<Task>();
        foreach (var d in devices)
        {
            tasks.Add(Task.Run(() => PingDevice(d), cancel));
            if (!d.IsThisPc)
            {
                tasks.Add(Task.Run(() => Netbios(d), cancel));
                tasks.Add(Task.Run(() => Mdns(d), cancel));
                tasks.Add(Task.Run(() => Llmnr(d), cancel));
                if (!d.IsGateway) tasks.Add(Task.Run(() => ReverseDns(d, r.Gateway), cancel));
            }
            if (ssdp.TryGetValue(d.Ip, out var loc)) tasks.Add(Task.Run(() => SsdpDescription(d, loc, cancel), cancel));
        }
        try { Task.WaitAll(tasks.ToArray(), cancel); } catch (AggregateException) { }

        progress?.Report("Probando unas pocas puertas de cada aparato...");
        ProbePorts(others, cancel);
        foreach (var d in devices) Classify(d);
        // El nombre de este PC lo sabemos sin preguntar
        var thisPc = devices.FirstOrDefault(d => d.IsThisPc);
        if (thisPc != null && thisPc.NetbiosName.Length == 0) thisPc.NetbiosName = Environment.MachineName;
        return devices.OrderBy(d => IpOrder(d.Ip)).ToList();
    }

    private static ScanDevice NewDevice(string ip, string mac, RouterReport r)
    {
        bool random = mac.Length >= 2 && (Convert.ToByte(mac[..2], 16) & 2) == 2;
        return new ScanDevice
        {
            Ip = ip, Mac = mac, Randomized = random,
            Vendor = random ? "" : RouterCheck.Vendor(mac),
            IsGateway = ip == r.Gateway, IsThisPc = ip == r.LocalIp,
        };
    }

    /// <summary>Nombre y tipo rápidos de un aparato (para el aviso de aparato nuevo del servicio).</summary>
    public static ScanDevice Quick(string ip, string mac, string gateway)
    {
        EnoughThreads();
        bool random = mac.Length >= 2 && (Convert.ToByte(mac[..2], 16) & 2) == 2;
        var d = new ScanDevice { Ip = ip, Mac = mac, Randomized = random, Vendor = random ? "" : RouterCheck.Vendor(mac) };
        try
        {
            Task.WaitAll(new[]
            {
                Task.Run(() => PingDevice(d)), Task.Run(() => Netbios(d)),
                Task.Run(() => Mdns(d)), Task.Run(() => ReverseDns(d, gateway)), Task.Run(() => Llmnr(d)),
            }, 4000);
            AddDhcp(new List<ScanDevice> { d });
            ProbePorts(new List<ScanDevice> { d }, default);
            Classify(d);
        }
        catch { }
        return d;
    }

    private static void AddDhcp(List<ScanDevice> devices)
    {
        var map = DhcpNames.Load();
        foreach (var d in devices)
            if (map.TryGetValue(d.Mac, out var n)) { d.DhcpName = n.Name; d.DhcpVendor = n.VendorClass; }
    }

    // ------------------------------------------------------------------ qué es cada MAC
    private static readonly (string[] Words, string Text)[] VendorHints =
    {
        (new[] { "Nintendo" }, "Nintendo fabrica consolas (Switch, Switch 2). Casi seguro una consola."),
        (new[] { "Sony Interactive" }, "Sony Interactive fabrica las PlayStation. Es una consola."),
        (new[] { "Arcadyan" }, "Arcadyan fabrica routers, repetidores Wi-Fi y descodificadores de TV para los operadores (Vodafone, Movistar, Orange...). También hizo el Wi-Fi de algunas consolas antiguas."),
        (new[] { "ZTE", "Sagemcom", "Mitrastar", "Askey", "Huawei Technologies" }, "Fabricante de routers y descodificadores de los operadores."),
        (new[] { "TP-LINK", "TP-Link", "Tenda", "D-Link", "Netgear", "Linksys", "AVM", "Ubiquiti", "Mercusys" }, "Fabricante de routers, repetidores Wi-Fi y PLC; también enchufes y cámaras (TP-Link)."),
        (new[] { "Apple" }, "Apple: iPhone, iPad, Mac, Apple TV o HomePod."),
        (new[] { "Samsung" }, "Samsung: móvil, tablet, tele, nevera o lavadora con Wi-Fi."),
        (new[] { "OPPO", "Xiaomi", "Honor", "Huawei Device", "OnePlus", "Motorola", "vivo", "Realme", "HMD", "Guangdong" }, "Fabricante de móviles (también tablets, relojes y aparatos de casa en el caso de Xiaomi)."),
        (new[] { "Espressif" }, "Espressif hace el chip Wi-Fi de muchos aparatos baratos de domótica: enchufes, bombillas, aspiradoras, termostatos, tiras de LED..."),
        (new[] { "Tuya", "Shelly", "Sonoff", "ITEAD", "Signify", "Philips Lighting" }, "Domótica: enchufes, bombillas o interruptores inteligentes."),
        (new[] { "Amazon" }, "Amazon: altavoz Alexa (Echo), Fire TV o Kindle."),
        (new[] { "Google" }, "Google: Chromecast, Google TV, altavoz Nest o móvil Pixel."),
        (new[] { "Intel", "Realtek", "Liteon", "AzureWave", "Hon Hai", "Qualcomm Atheros", "MEDIATEK", "Rivet", "CyberTAN" }, "Fabricante de tarjetas de red (Wi-Fi o cable) que llevan los ordenadores. Casi seguro un PC o portátil."),
        (new[] { "GIGA-BYTE", "Gigabyte", "ASUSTek", "Micro-Star", "ASRock", "Dell", "Hewlett", "Lenovo", "Acer", "TOSHIBA", "Dynabook" }, "Fabricante de ordenadores o placas base. Casi seguro un PC o portátil."),
        (new[] { "Hikvision", "Dahua", "Ezviz", "Wyze", "Ring" }, "Fabricante de cámaras de vigilancia o timbres con cámara."),
        (new[] { "Sonos" }, "Altavoz Sonos."),
        (new[] { "LG Electronics", "Hisense", "TCL", "Vestel", "Panasonic", "Sharp", "Philips", "Sony" }, "Fabricante de teles (y otros aparatos de casa)."),
        (new[] { "Epson", "Canon", "Brother", "Seiko Epson", "Kyocera" }, "Fabricante de impresoras."),
    };

    public static string ExplainMac(ScanDevice d)
    {
        if (d.Randomized)
            return "Es una MAC PRIVADA: el propio aparato se la inventa para que no lo puedan seguir de un Wi-Fi a otro " +
                   "(lo hacen los móviles Android, los iPhone y algunos PCs con Windows 11). Por eso no se sabe el fabricante. " +
                   "El nombre lo dice al conectarse al Wi-Fi" + (d.DhcpName.Length > 0 ? $": \"{d.DhcpName}\"." : " (aún no se ha oído; sale en cuanto se vuelva a conectar).");
        if (d.Vendor.Length == 0)
            return "Fabricante desconocido: su prefijo no está en la lista del programa (puede ser muy nuevo o de una marca pequeña).";
        var hint = VendorHints.FirstOrDefault(h => h.Words.Any(w => d.Vendor.Contains(w, StringComparison.OrdinalIgnoreCase)));
        return $"{d.Vendor}." + (hint.Text != null ? " " + hint.Text : "");
    }

    // ------------------------------------------------------------------ ping (TTL y lo que tarda)
    private static void PingDevice(ScanDevice d)
    {
        try
        {
            using var p = new Ping();
            var reply = p.Send(d.Ip, 1000);
            if (reply.Status == IPStatus.Success)
            {
                d.PingMs = reply.RoundtripTime;
                d.Ttl = reply.Options?.Ttl ?? 0;
            }
        }
        catch { }
    }

    // ------------------------------------------------------------------ nombre por la red de Windows (NetBIOS)
    private static void Netbios(ScanDevice d)
    {
        // Petición "dime todos tus nombres" (NBSTAT) al puerto 137 del aparato
        var q = new List<byte> { 0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x20 };
        q.Add((byte)'C'); q.Add((byte)'K');
        for (int i = 0; i < 30; i++) q.Add((byte)'A');
        q.AddRange(new byte[] { 0x00, 0x00, 0x21, 0x00, 0x01 });
        byte[]? res = UdpAsk(d.Ip, 137, q.ToArray(), 1200);
        if (res == null || res.Length < 57) return;
        try
        {
            int o = 12;
            SkipName(res, ref o);
            o += 2 + 2 + 4 + 2; // tipo, clase, TTL, longitud
            int n = res[o++];
            for (int i = 0; i < n && o + 18 <= res.Length; i++, o += 18)
            {
                string name = Encoding.ASCII.GetString(res, o, 15).Trim(' ', '\0');
                byte suffix = res[o + 15];
                bool group = (res[o + 16] & 0x80) != 0;
                if (suffix != 0 || name.Length == 0) continue;
                if (group) { if (d.Workgroup.Length == 0) d.Workgroup = name; }
                else if (d.NetbiosName.Length == 0) d.NetbiosName = name;
            }
        }
        catch { }
    }

    // ------------------------------------------------------------------ nombre por Bonjour (mDNS)
    private static void Mdns(ScanDevice d)
    {
        // Se pregunta directamente al aparato (no a toda la red) su nombre y qué servicios ofrece
        var ptr = ReverseName(d.Ip);
        using var udp = new UdpClient(0);
        udp.Client.ReceiveTimeout = 400;
        var ep = new IPEndPoint(IPAddress.Parse(d.Ip), 5353);
        try
        {
            byte[] a = DnsQuery(0x4646, ptr, 12);
            byte[] b = DnsQuery(0x4647, "_services._dns-sd._udp.local", 12);
            udp.Send(a, a.Length, ep);
            udp.Send(b, b.Length, ep);
        }
        catch { return; }
        var end = DateTime.UtcNow.AddMilliseconds(1500);
        while (DateTime.UtcNow < end)
        {
            byte[] res;
            try { var from = new IPEndPoint(IPAddress.Any, 0); res = udp.Receive(ref from); if (from.Address.ToString() != d.Ip) continue; }
            catch (SocketException) { if (d.MdnsName.Length > 0 && d.Services.Count > 0) break; continue; }
            catch { break; }
            foreach (var (name, type, data) in DnsAnswers(res))
            {
                if (type != 12 || data.Length == 0) continue;
                if (name.Equals(ptr, StringComparison.OrdinalIgnoreCase) && d.MdnsName.Length == 0)
                    d.MdnsName = Regex.Replace(data, @"\.local\.?$", "", RegexOptions.IgnoreCase);
                else if (name.StartsWith("_services._dns-sd", StringComparison.OrdinalIgnoreCase))
                    lock (d.Services) { if (!d.Services.Contains(data)) d.Services.Add(data); }
            }
        }
    }

    // ------------------------------------------------------------------ nombre de los PCs Windows (LLMNR)
    /// <summary>Windows 10/11 dice su nombre por LLMNR (puerto 5355) aunque tenga apagado NetBIOS.</summary>
    private static void Llmnr(ScanDevice d)
    {
        if (d.LlmnrName.Length > 0) return;
        byte[]? res = UdpAsk(d.Ip, 5355, DnsQuery(0x6161, ReverseName(d.Ip), 12), 1000);
        if (res == null) return;
        foreach (var (_, type, data) in DnsAnswers(res))
            if (type == 12 && data.Length > 0) { d.LlmnrName = data.TrimEnd('.'); return; }
    }

    // ------------------------------------------------------------------ nombre que le ha dado el router (DNS)
    private static void ReverseDns(ScanDevice d, string gateway)
    {
        if (gateway.Length == 0) return;
        byte[]? res = UdpAsk(gateway, 53, DnsQuery(0x5151, ReverseName(d.Ip), 12, recursion: true), 1000);
        if (res == null) return;
        foreach (var (_, type, data) in DnsAnswers(res))
        {
            if (type != 12 || data.Length == 0) continue;
            string n = data.TrimEnd('.');
            // Algunos routers contestan con la IP o con un nombre inventado a partir de ella
            if (Regex.IsMatch(n, @"\d+[-.]\d+[-.]\d+[-.]\d+")) continue;
            d.DnsName = Regex.Replace(n, @"\.(home|lan|local|localdomain|router|domain|station)$", "", RegexOptions.IgnoreCase);
            return;
        }
    }

    // ------------------------------------------------------------------ UPnP: nombre y modelo (teles, consolas, NAS...)
    private static readonly HttpClient Http = new(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
    { Timeout = TimeSpan.FromSeconds(3), MaxResponseContentBufferSize = 512 * 1024 };

    private static Dictionary<string, string> ReadSsdp(string localIp, CancellationToken cancel)
    {
        var map = new Dictionary<string, string>();
        try
        {
            using var udp = new UdpClient(new IPEndPoint(localIp.Length > 0 ? IPAddress.Parse(localIp) : IPAddress.Any, 0));
            udp.Client.ReceiveTimeout = 500;
            byte[] msg = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n");
            var target = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
            udp.Send(msg, msg.Length, target);
            udp.Send(msg, msg.Length, target);
            var end = DateTime.UtcNow.AddSeconds(3);
            while (DateTime.UtcNow < end && !cancel.IsCancellationRequested)
            {
                try
                {
                    var from = new IPEndPoint(IPAddress.Any, 0);
                    string text = Encoding.ASCII.GetString(udp.Receive(ref from));
                    var m = Regex.Match(text, @"^LOCATION:\s*(\S+)", RegexOptions.IgnoreCase | RegexOptions.Multiline);
                    string ip = from.Address.ToString();
                    if (m.Success && !map.ContainsKey(ip)) map[ip] = m.Groups[1].Value;
                }
                catch (SocketException) { }
            }
        }
        catch { }
        return map;
    }

    private static void SsdpDescription(ScanDevice d, string location, CancellationToken cancel)
    {
        // Solo se lee la ficha del propio aparato, nunca de otro sitio
        if (!Uri.TryCreate(location, UriKind.Absolute, out var uri) || uri.Scheme != "http" || uri.Host != d.Ip) return;
        try
        {
            var doc = XDocument.Parse(Http.GetStringAsync(uri, cancel).GetAwaiter().GetResult());
            var dev = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
            string F(string n) => dev?.Elements().FirstOrDefault(e => e.Name.LocalName == n)?.Value.Trim() ?? "";
            d.SsdpName = F("friendlyName");
            d.SsdpModel = string.Join(" ", new[] { F("manufacturer"), F("modelName") }.Where(s => s.Length > 0).Distinct());
            string type = F("deviceType");
            if (type.Length > 0) lock (d.Services) d.Services.Add("upnp:" + type.Split(':').Reverse().Skip(1).FirstOrDefault());
        }
        catch { }
    }

    // ------------------------------------------------------------------ puertas
    private static void ProbePorts(List<ScanDevice> devices, CancellationToken cancel)
    {
        var jobs = devices.SelectMany(d => Ports.Select(p => (d, p.Port))).ToList();
        var open = new ConcurrentBag<(ScanDevice, int)>();
        try
        {
            Parallel.ForEach(jobs, new ParallelOptions { MaxDegreeOfParallelism = 96, CancellationToken = cancel }, job =>
            {
                using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    var t = s.ConnectAsync(new IPEndPoint(IPAddress.Parse(job.d.Ip), job.Port));
                    if (t.Wait(800) && s.Connected) open.Add((job.d, job.Port));
                }
                catch { }
            });
        }
        catch (OperationCanceledException) { }
        foreach (var g in open.GroupBy(x => x.Item1))
            g.Key.OpenPorts = g.Select(x => x.Item2).Distinct().OrderBy(p => p).ToList();
    }

    // ------------------------------------------------------------------ qué tipo de aparato es
    private static bool Has(string text, params string[] words) => words.Any(w => text.Contains(w, StringComparison.OrdinalIgnoreCase));

    public static void Classify(ScanDevice d)
    {
        string names = $"{d.DhcpName} {d.DhcpVendor} {d.MdnsName} {d.NetbiosName} {d.LlmnrName} {d.DnsName} {d.SsdpName} {d.SsdpModel}";
        string svc;
        lock (d.Services) svc = string.Join(" ", d.Services);
        string v = d.Vendor;
        var p = d.OpenPorts;

        (DeviceGroup, string) Pick()
        {
            if (d.IsGateway) return (DeviceGroup.Router, "Router");
            if (d.IsThisPc) return (DeviceGroup.Ordenadores, "Ordenador (este PC)");
            if (Has(names, "playstation", "ps4", "ps5", "ps3") || Has(v, "Sony Interactive") || p.Contains(9295)) return (DeviceGroup.TeleConsolas, "Consola PlayStation");
            if (Has(names, "xbox")) return (DeviceGroup.TeleConsolas, "Consola Xbox");
            if (Has(names, "nintendo", "switch") || Has(v, "Nintendo")) return (DeviceGroup.TeleConsolas, "Consola Nintendo");
            if (Has(svc, "_googlecast") || p.Contains(8009) || Has(names, "chromecast", "google tv")) return (DeviceGroup.TeleConsolas, "Tele o Chromecast");
            if (Regex.IsMatch(names, @"(^|[\s\-_.])(tv|smarttv)([\s\-_.]|$)", RegexOptions.IgnoreCase) || Has(names, "bravia", "webos", "tizen", "smarttv", "fire tv", "roku") || Has(svc, "MediaRenderer") && !Has(names, "pc", "desktop", "laptop"))
                return (DeviceGroup.TeleConsolas, "Tele");
            if (Has(svc, "_ipp", "_printer", "_pdl-datastream") || p.Contains(9100) || p.Contains(631) || p.Contains(515) ||
                Has(names, "printer", "impresora", "epson", "laserjet", "deskjet", "officejet", "brother", "canon"))
                return (DeviceGroup.Impresoras, "Impresora");
            if (p.Contains(62078) || Has(names, "iphone", "ipad")) return (DeviceGroup.Moviles, Has(names, "ipad") ? "iPad" : "iPhone o iPad");
            if (Has(names, "android", "galaxy", "redmi", "xiaomi", "oppo", "honor", "huawei", "pixel", "oneplus", "realme", "moto", "phone", "movil", "tablet", "tab-"))
                return (DeviceGroup.Moviles, "Móvil o tablet");
            if (p.Contains(445) || p.Contains(139) || p.Contains(3389) || d.NetbiosName.Length > 0 || d.LlmnrName.Length > 0 || Has(names, "desktop-", "laptop-", "-pc", "pc-", "macbook", "imac", "MSFT 5.0"))
                return (DeviceGroup.Ordenadores, Has(names, "macbook", "imac") ? "Mac" : "Ordenador");
            if (Has(svc, "_airplay", "_raop", "_sleep-proxy")) return (DeviceGroup.TeleConsolas, "Apple TV o altavoz AirPlay");
            if (Has(svc, "_hap", "_homekit", "_amzn", "_spotify-connect") || p.Contains(1883) || p.Contains(554) ||
                Has(v, "Espressif", "Tuya", "Shelly", "Sonoff", "Amazon", "Google", "Sonos", "Philips Lighting", "Signify", "TP-Link Systems", "Ring", "Wyze", "Hikvision", "Dahua", "Ezviz") ||
                Has(names, "echo", "alexa", "nest", "camera", "camara", "cam-", "plug", "bombilla", "sonos"))
                return (DeviceGroup.Otros, p.Contains(554) || Has(v, "Hikvision", "Dahua", "Ezviz") || Has(names, "cam") ? "Cámara" :
                    Has(v, "Amazon") || Has(names, "echo", "alexa") ? "Altavoz Alexa o Fire TV" :
                    Has(v, "Google") || Has(names, "nest") ? "Aparato de Google (altavoz, Chromecast)" : "Aparato de domótica");
            if (Has(v, "Sony") || Has(v, "LG Electronics") || Has(v, "Hisense", "TCL", "Vestel", "Panasonic", "Philips", "Sharp", "Toshiba")) return (DeviceGroup.TeleConsolas, "Tele (por el fabricante)");
            if (Has(v, "Apple")) return (DeviceGroup.Moviles, "Aparato Apple (iPhone, iPad o Mac)");
            if (Has(v, "Samsung", "OPPO", "Xiaomi", "Huawei", "Honor", "OnePlus", "Motorola", "vivo", "Realme", "Guangdong", "Beijing", "HMD", "Nokia", "Lenovo Mobile", "Google"))
                return (DeviceGroup.Moviles, "Móvil o tablet (por el fabricante)");
            if (Has(v, "Intel", "Realtek", "GIGA-BYTE", "ASUSTek", "Micro-Star", "Liteon", "AzureWave", "CyberTAN", "Hon Hai", "Dell", "Hewlett", "Lenovo", "Acer", "Gigabyte", "ASRock", "Rivet", "Qualcomm Atheros", "MEDIATEK"))
                return (DeviceGroup.Ordenadores, "Ordenador (por el fabricante)");
            if (Has(v, "Arcadyan", "ZTE", "Sagemcom", "Huawei Device", "AVM", "TP-LINK", "TP-Link", "Netgear", "Ubiquiti", "Mitrastar", "Askey", "Tenda", "D-Link", "Linksys"))
                return (DeviceGroup.Otros, "Aparato de red (repetidor, PLC, router o descodificador)");
            if (d.Randomized) return (DeviceGroup.Moviles, "Móvil, tablet o PC con dirección privada");
            return (DeviceGroup.Desconocidos, "");
        }
        (d.Group, d.TypeText) = Pick();
    }

    // ------------------------------------------------------------------ ayudas DNS/UDP
    private static byte[]? UdpAsk(string ip, int port, byte[] query, int timeoutMs)
    {
        try
        {
            using var udp = new UdpClient(0);
            udp.Client.ReceiveTimeout = timeoutMs;
            var ep = new IPEndPoint(IPAddress.Parse(ip), port);
            udp.Send(query, query.Length, ep);
            var from = new IPEndPoint(IPAddress.Any, 0);
            var res = udp.Receive(ref from);
            return from.Address.Equals(ep.Address) ? res : null;
        }
        catch { return null; }
    }

    private static string ReverseName(string ip) => string.Join(".", ip.Split('.').Reverse()) + ".in-addr.arpa";

    private static byte[] DnsQuery(ushort id, string name, ushort type, bool recursion = false)
    {
        var q = new List<byte> { (byte)(id >> 8), (byte)id, (byte)(recursion ? 1 : 0), 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var b = Encoding.UTF8.GetBytes(label);
            q.Add((byte)b.Length);
            q.AddRange(b);
        }
        q.Add(0);
        q.Add((byte)(type >> 8)); q.Add((byte)type);
        q.Add(0); q.Add(1);
        return q.ToArray();
    }

    private static void SkipName(byte[] b, ref int o)
    {
        while (o < b.Length)
        {
            int len = b[o];
            if (len == 0) { o++; return; }
            if ((len & 0xC0) == 0xC0) { o += 2; return; }
            o += len + 1;
        }
    }

    private static string ReadName(byte[] b, int o)
    {
        var parts = new List<string>();
        for (int guard = 0; o < b.Length && guard < 64; guard++)
        {
            int len = b[o];
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) { if (o + 1 >= b.Length) break; o = ((len & 0x3F) << 8) | b[o + 1]; continue; }
            if (o + 1 + len > b.Length) break;
            parts.Add(Encoding.UTF8.GetString(b, o + 1, len));
            o += len + 1;
        }
        return string.Join(".", parts);
    }

    /// <summary>Todas las respuestas (las tres secciones) de un mensaje DNS: nombre, tipo y, si es PTR, el nombre apuntado.</summary>
    private static List<(string Name, int Type, string Data)> DnsAnswers(byte[] b)
    {
        var list = new List<(string, int, string)>();
        try
        {
            if (b.Length < 12) return list;
            int qd = (b[4] << 8) | b[5];
            int rr = ((b[6] << 8) | b[7]) + ((b[8] << 8) | b[9]) + ((b[10] << 8) | b[11]);
            int o = 12;
            for (int i = 0; i < qd; i++) { SkipName(b, ref o); o += 4; }
            for (int i = 0; i < rr && o < b.Length; i++)
            {
                string name = ReadName(b, o);
                SkipName(b, ref o);
                if (o + 10 > b.Length) break;
                int type = (b[o] << 8) | b[o + 1];
                int len = (b[o + 8] << 8) | b[o + 9];
                o += 10;
                if (o + len > b.Length) break;
                list.Add((name, type, type == 12 ? ReadName(b, o) : ""));
                o += len;
            }
        }
        catch { }
        return list;
    }

    public static uint IpOrder(string ip)
    {
        if (!IPAddress.TryParse(ip, out var a)) return 0;
        var b = a.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }
}
