using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace FirewallFamiliar.Core;

/// <summary>Lo que se recuerda de un aparato de casa (por su MAC).</summary>
public sealed class DeviceEntry
{
    /// <summary>Nombre que le ha puesto Jose ("Móvil de Elena", "PS3 del salón"...).</summary>
    public string Name { get; set; } = "";
    /// <summary>Jose ha dicho que es de casa.</summary>
    public bool Home { get; set; }
    public string Network { get; set; } = "";
    public string LastIp { get; set; } = "";
    public string HostName { get; set; } = "";
    public string Type { get; set; } = "";
    public DeviceGroup Group { get; set; } = DeviceGroup.Desconocidos;
    public string Vendor { get; set; } = "";
    public List<int> Ports { get; set; } = new();
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
}

/// <summary>
/// Libreta de aparatos de casa: C:\ProgramData\FirewallFamiliar\aparatos.json.
/// La rellena el escaneo de la ventana Router; el servicio solo la lee (para el informe y los avisos).
/// </summary>
public static class DeviceBook
{
    public static readonly string FilePath = Path.Combine(RuleStore.Folder, "aparatos.json");
    private static readonly object Lock = new();

    public static Dictionary<string, DeviceEntry> Load()
    {
        lock (Lock)
        {
            try
            {
                if (File.Exists(FilePath))
                    return JsonSerializer.Deserialize<Dictionary<string, DeviceEntry>>(File.ReadAllText(FilePath)) ?? new();
            }
            catch { }
            return new();
        }
    }

    public static void Save(Dictionary<string, DeviceEntry> book)
    {
        lock (Lock)
        {
            try
            {
                Directory.CreateDirectory(RuleStore.Folder);
                string tmp = FilePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(book, new JsonSerializerOptions { WriteIndented = true }));
                File.Move(tmp, FilePath, true);
            }
            catch { }
        }
    }

    /// <summary>
    /// Junta el escaneo con la libreta: guarda lo nuevo, pone a cada aparato su nombre de la libreta y
    /// añade como "no responde" los aparatos de esta red que se conocían y ahora no han contestado.
    /// </summary>
    public static List<ScanDevice> Merge(List<ScanDevice> scan, string network)
    {
        var book = Load();
        var now = DateTime.Now;
        foreach (var d in scan)
        {
            if (!book.TryGetValue(d.Mac, out var e)) book[d.Mac] = e = new DeviceEntry { FirstSeen = now };
            e.Network = network;
            e.LastIp = d.Ip;
            e.LastSeen = now;
            if (d.HostName.Length > 0) e.HostName = d.HostName;
            if (d.TypeText.Length > 0 || e.Type.Length == 0) { e.Type = d.TypeText; e.Group = d.Group; }
            if (d.Vendor.Length > 0) e.Vendor = d.Vendor;
            e.Ports = d.OpenPorts.ToList();
            d.Label = e.Name;
            d.Home = e.Home;
            d.FirstSeen = e.FirstSeen;
            d.LastSeen = e.LastSeen;
            // Si esta vez no dice su nombre ni se sabe qué es, vale lo que se supo otra vez
            if (d.HostName.Length == 0 && e.HostName.Length > 0) d.OldName = e.HostName;
            if (d.TypeText.Length == 0 && e.Type.Length > 0) { d.TypeText = e.Type; d.Group = e.Group; }
        }
        Save(book);
        var result = scan.ToList();
        foreach (var (mac, e) in book.Where(x => x.Value.Network == network && !scan.Any(d => d.Mac == x.Key)))
        {
            result.Add(new ScanDevice
            {
                Ip = e.LastIp, Mac = mac, Vendor = e.Vendor, Answered = false,
                Randomized = mac.Length >= 2 && (Convert.ToByte(mac[..2], 16) & 2) == 2,
                OldName = e.HostName, TypeText = e.Type, Group = e.Group, OpenPorts = e.Ports.ToList(),
                Label = e.Name, Home = e.Home, FirstSeen = e.FirstSeen, LastSeen = e.LastSeen,
            });
        }
        // El router puede contestar con dos MAC: una sola entrada por router (la que contesta, primero)
        return result.GroupBy(d => d.Group == DeviceGroup.Router ? "router " + d.Ip : d.Mac).Select(g => g.First()).ToList();
    }

    public static void SetName(string mac, string name, bool home)
    {
        var book = Load();
        if (!book.TryGetValue(mac, out var e)) book[mac] = e = new DeviceEntry { FirstSeen = DateTime.Now, LastSeen = DateTime.Now };
        e.Name = name.Trim();
        e.Home = home;
        Save(book);
    }

    public static void Forget(string mac)
    {
        var book = Load();
        if (book.Remove(mac)) Save(book);
    }

    /// <summary>Nombre para un aviso o el informe: el que puso Jose, o el que dio el aparato.</summary>
    public static string NameOf(Dictionary<string, DeviceEntry> book, string mac) =>
        book.TryGetValue(mac, out var e) ? (e.Name.Length > 0 ? e.Name : e.HostName) : "";
}
