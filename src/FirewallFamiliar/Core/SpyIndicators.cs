using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace FirewallFamiliar.Core;

/// <summary>
/// Listas públicas de programas espía: dominios, IPs y huellas (SHA-256) que Amnesty International,
/// Citizen Lab y ECHAP han publicado en sus investigaciones (Pegasus, Predator, stalkerware...).
/// Van dentro del programa (Assets/indicadores.txt, generado con tools/indicadores.py) y se
/// actualizan con cada versión. Las apps de control parental (Microsoft Family, Life360, Qustodio...)
/// están excluidas a propósito.
/// </summary>
public static class SpyIndicators
{
    private static readonly Dictionary<string, string> Domains = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<IPAddress, string> Ips = new();
    private static readonly Dictionary<string, string> Hashes = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>IPs que han resuelto dominios de la lista en este PC (también se bloquean).</summary>
    private static readonly Dictionary<IPAddress, string> Learned = new();
    private static readonly object Gate = new();

    static SpyIndicators()
    {
        try
        {
            using var s = typeof(SpyIndicators).Assembly.GetManifestResourceStream("FirewallFamiliar.indicadores.txt");
            if (s == null) return;
            using var r = new StreamReader(s);
            for (string? line = r.ReadLine(); line != null; line = r.ReadLine())
            {
                if (line.Length == 0 || line[0] == '#') continue;
                var p = line.Split('\t');
                if (p.Length < 3) continue;
                switch (p[0])
                {
                    case "domain": Domains[p[1]] = p[2]; break;
                    case "ip": if (IPAddress.TryParse(p[1], out var ip)) Ips[Normal(ip)] = p[2]; break;
                    case "sha256": Hashes[p[1]] = p[2]; break;
                }
            }
        }
        catch { }
    }

    public static int DomainCount => Domains.Count;
    public static int IpCount => Ips.Count;
    public static int HashCount => Hashes.Count;

    private static IPAddress Normal(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    /// <summary>Si el nombre (o un dominio superior suyo) está en la lista: (dominio de la lista, familia).</summary>
    public static (string Domain, string Family)? MatchDomain(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        string d = name.Trim().TrimEnd('.').ToLowerInvariant();
        while (d.Contains('.'))
        {
            if (Domains.TryGetValue(d, out var family)) return (d, family);
            d = d[(d.IndexOf('.') + 1)..];
        }
        return null;
    }

    /// <summary>Familia de programa espía si la IP está en la lista (o la ha resuelto un dominio de la lista).</summary>
    public static string? MatchIp(IPAddress? ip)
    {
        if (ip == null) return null;
        ip = Normal(ip);
        if (Ips.TryGetValue(ip, out var f)) return f;
        lock (Gate) return Learned.TryGetValue(ip, out f) ? f : null;
    }

    /// <summary>Apunta una IP que ha resuelto un dominio de la lista. Devuelve true si es nueva.</summary>
    public static bool Learn(IPAddress ip, string family)
    {
        ip = Normal(ip);
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || IpInfo.Special(ip) != null) return false;
        if (Ips.ContainsKey(ip)) return false;
        lock (Gate)
        {
            if (Learned.ContainsKey(ip) || Learned.Count > 2000) return false;
            Learned[ip] = family;
            return true;
        }
    }

    /// <summary>Todas las IPs a bloquear: las de la lista y las aprendidas.</summary>
    public static List<IPAddress> BlockList()
    {
        lock (Gate) return Ips.Keys.Concat(Learned.Keys).Distinct().ToList();
    }

    /// <summary>Familia de programa espía si la huella SHA-256 del archivo está en la lista.</summary>
    public static string? MatchFile(string path)
    {
        if (Hashes.Count == 0 || string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        try
        {
            var info = new FileInfo(path);
            if (info.Length > 300L * 1024 * 1024) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            string hash = Convert.ToHexString(SHA256.HashData(fs));
            return Hashes.TryGetValue(hash, out var family) ? family : null;
        }
        catch { return null; }
    }
}
