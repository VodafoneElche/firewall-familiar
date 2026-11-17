using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace FirewallFamiliar.Core;

/// <summary>Nombre que un aparato dijo al conectarse a la red de casa (DHCP).</summary>
public sealed class DhcpName
{
    public string Name { get; set; } = "";
    /// <summary>Qué sistema dice ser ("android-dhcp-14", "MSFT 5.0"...).</summary>
    public string VendorClass { get; set; } = "";
    public string Ip { get; set; } = "";
    public DateTime Time { get; set; }
}

/// <summary>
/// Nombres de los aparatos de casa, oídos cuando se conectan.
/// Cada móvil, tablet o PC, al conectarse al Wi-Fi, le pide una dirección al router con un mensaje
/// a TODA la red (DHCP) donde dice su nombre ("Tab-S9-de-Alejandro", "HONOR-Magic8-Lite"...).
/// Es el nombre que sale en la página del router. El servicio solo escucha esos mensajes (no
/// contesta nada, el router sigue siendo quien reparte las direcciones) y apunta MAC → nombre en
/// C:\ProgramData\FirewallFamiliar\nombres-dhcp.json. Solo en la red de casa.
/// </summary>
public static class DhcpNames
{
    public static readonly string FilePath = Path.Combine(RuleStore.Folder, "nombres-dhcp.json");
    private const string RuleName = "Firewall Familiar - nombres de los aparatos de casa (DHCP)";
    private static readonly object Lock = new();

    public static Dictionary<string, DhcpName> Load()
    {
        lock (Lock)
        {
            try
            {
                if (File.Exists(FilePath))
                    return JsonSerializer.Deserialize<Dictionary<string, DhcpName>>(File.ReadAllText(FilePath)) ?? new();
            }
            catch { }
            return new();
        }
    }

    private static void Save(Dictionary<string, DhcpName> map)
    {
        lock (Lock)
        {
            try
            {
                string tmp = FilePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(map, new JsonSerializerOptions { WriteIndented = true }));
                File.Move(tmp, FilePath, true);
            }
            catch { }
        }
    }

    // ------------------------------------------------------------------ servicio: escuchar
    /// <summary>
    /// Bucle del servicio (en su propio hilo). Se escucha en la dirección de este PC en la red de
    /// casa, puerto 67: así no se molesta a la "zona Wi-Fi móvil" de Windows, que usa otra dirección.
    /// </summary>
    public static void Listen(CancellationToken stop, Action<string> log)
    {
        AllowInWindowsFirewall(log);
        var map = Load();
        while (!stop.IsCancellationRequested)
        {
            var (_, key, localIp) = RouterCheck.CurrentLocal();
            string? home = RouterCheck.HomeNetwork();
            if (localIp.Length == 0 || key.Length == 0 || (home != null && !RouterCheck.SameNet(home, key)))
            {
                stop.WaitHandle.WaitOne(TimeSpan.FromMinutes(1));
                continue;
            }
            UdpClient udp;
            try
            {
                udp = new UdpClient { ExclusiveAddressUse = false };
                udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                udp.Client.Bind(new IPEndPoint(IPAddress.Parse(localIp), 67));
                udp.Client.ReceiveTimeout = 60000;
            }
            catch (Exception ex)
            {
                log("Nombres de aparatos: no se puede escuchar en el puerto 67: " + ex.Message);
                stop.WaitHandle.WaitOne(TimeSpan.FromMinutes(30));
                continue;
            }
            log($"Nombres de aparatos: escuchando en {localIp}:67 cuándo se conectan los aparatos de casa ({map.Count} nombres apuntados).");
            using (udp)
            using (stop.Register(() => { try { udp.Close(); } catch { } }))
            {
                var checkedAt = DateTime.UtcNow;
                while (!stop.IsCancellationRequested)
                {
                    try
                    {
                        var from = new IPEndPoint(IPAddress.Any, 0);
                        var packet = udp.Receive(ref from);
                        var found = Parse(packet);
                        if (found is { } f && f.Mac.Length > 0 && f.Name.Length > 0)
                        {
                            bool changed = !map.TryGetValue(f.Mac, out var old) || old.Name != f.Name || old.VendorClass != f.Vendor ||
                                           DateTime.Now - old.Time > TimeSpan.FromHours(6);
                            map[f.Mac] = new DhcpName { Name = f.Name, VendorClass = f.Vendor, Ip = f.Ip.Length > 0 ? f.Ip : old?.Ip ?? "", Time = DateTime.Now };
                            if (changed)
                            {
                                Save(map);
                                if (old == null || old.Name != f.Name) log($"Nombres de aparatos: {f.Mac} se llama \"{f.Name}\"{(f.Vendor.Length > 0 ? $" ({f.Vendor})" : "")}.");
                            }
                        }
                    }
                    catch (SocketException) { }
                    catch (ObjectDisposedException) { break; }
                    catch { }
                    // Cada minuto: ¿sigue este PC en casa y con la misma dirección?
                    if (DateTime.UtcNow - checkedAt > TimeSpan.FromMinutes(1))
                    {
                        checkedAt = DateTime.UtcNow;
                        var (_, k2, ip2) = RouterCheck.CurrentLocal();
                        if (ip2 != localIp || k2 != key) break;
                    }
                }
            }
        }
    }

    /// <summary>Lee un mensaje DHCP de un aparato: su MAC, su nombre (opción 12 u 81), su sistema (60) y la IP que pide (50).</summary>
    private static (string Mac, string Name, string Vendor, string Ip)? Parse(byte[] p)
    {
        if (p.Length < 244 || p[0] != 1 || p[1] != 1 || p[2] != 6) return null; // petición, Ethernet, MAC de 6
        if (p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63) return null;
        string mac = string.Join("-", p.Skip(28).Take(6).Select(b => b.ToString("X2")));
        string name = "", fqdn = "", vendor = "", ip = "";
        if (p[12] != 0 || p[13] != 0 || p[14] != 0 || p[15] != 0) ip = $"{p[12]}.{p[13]}.{p[14]}.{p[15]}";
        int o = 240;
        while (o < p.Length)
        {
            byte code = p[o++];
            if (code == 0) continue;
            if (code == 255 || o >= p.Length) break;
            int len = p[o++];
            if (o + len > p.Length) break;
            switch (code)
            {
                case 12: name = Clean(Encoding.UTF8.GetString(p, o, len)); break;
                case 60: vendor = Clean(Encoding.ASCII.GetString(p, o, len)); break;
                case 50 when len == 4: ip = $"{p[o]}.{p[o + 1]}.{p[o + 2]}.{p[o + 3]}"; break;
                case 81 when len > 3: fqdn = Clean(ReadFqdn(p, o + 3, len - 3)); break;
            }
            o += len;
        }
        if (name.Length == 0) name = fqdn.Split('.')[0];
        return (mac, name, vendor, ip);
    }

    private static string ReadFqdn(byte[] p, int o, int len)
    {
        // Puede ir en texto o en formato DNS (longitud + etiqueta)
        if (len > 0 && p[o] < 64 && p[o] > 0 && p[o] < len)
        {
            var parts = new List<string>();
            int end = o + len;
            while (o < end && p[o] != 0 && o + 1 + p[o] <= end) { parts.Add(Encoding.UTF8.GetString(p, o + 1, p[o])); o += p[o] + 1; }
            return string.Join(".", parts);
        }
        return Encoding.UTF8.GetString(p, o, len);
    }

    private static string Clean(string s) => new string(s.Where(c => !char.IsControl(c)).ToArray()).Trim();

    // ------------------------------------------------------------------ cortafuegos de Windows
    /// <summary>
    /// El cortafuegos de Windows no deja llegar esos mensajes a un servicio sin permiso. Se le da
    /// permiso solo a Firewall Familiar, solo para el puerto 67 y solo en redes privadas (casa).
    /// </summary>
    private static void AllowInWindowsFirewall(Action<string> log)
    {
        string exe = Environment.ProcessPath ?? "";
        if (exe.Length == 0) return;
        Netsh($"advfirewall firewall delete rule name=\"{RuleName}\"");
        int rc = Netsh($"advfirewall firewall add rule name=\"{RuleName}\" dir=in action=allow protocol=UDP localport=67 " +
                       $"program=\"{exe}\" profile=private,domain");
        if (rc != 0) log("Nombres de aparatos: el cortafuegos de Windows no ha dejado añadir el permiso (código " + rc + ").");
    }

    /// <summary>Al desinstalar: se quita el permiso del cortafuegos de Windows.</summary>
    public static void RemoveFirewallRule() => Netsh($"advfirewall firewall delete rule name=\"{RuleName}\"");

    private static int Netsh(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("netsh.exe", args)
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true })!;
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            return p.ExitCode;
        }
        catch { return -1; }
    }
}
