using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace FirewallFamiliar.Core;

/// <summary>Datos de un programa a partir de su archivo .exe.</summary>
public sealed record FileInfoDetails(string Description, string Company, string Product, string Version, DateTime? Modified);

public static class FileDetails
{
    private static readonly ConcurrentDictionary<string, string> CaseCache = new(StringComparer.OrdinalIgnoreCase);

    public static FileInfoDetails Read(string path)
    {
        string desc = "", company = "", product = "", version = "";
        DateTime? modified = null;
        if (string.Equals(path, "System", StringComparison.OrdinalIgnoreCase))
            return new FileInfoDetails("Núcleo de Windows", "Microsoft Corporation", "Windows", "", null);
        try
        {
            var v = FileVersionInfo.GetVersionInfo(path);
            desc = v.FileDescription ?? "";
            company = v.CompanyName ?? "";
            product = v.ProductName ?? "";
            version = v.FileVersion ?? "";
        }
        catch { }
        try { modified = File.GetLastWriteTime(path); } catch { }
        return new FileInfoDetails(desc, company, product, version, modified);
    }

    /// <summary>
    /// Windows nos da algunas rutas en minúsculas ("c:\program files\..."). Esto recupera
    /// las mayúsculas reales mirando el disco carpeta a carpeta.
    /// </summary>
    public static string ProperCase(string path)
    {
        if (string.IsNullOrEmpty(path) || path.Length < 3 || path[1] != ':') return path;
        return CaseCache.GetOrAdd(path, p =>
        {
            try
            {
                var parts = p.Split('\\', StringSplitOptions.RemoveEmptyEntries);
                string current = char.ToUpperInvariant(parts[0][0]) + ":\\";
                for (int i = 1; i < parts.Length; i++)
                {
                    string? match = Directory.EnumerateFileSystemEntries(current, parts[i]).FirstOrDefault();
                    if (match == null) return p;
                    current = match;
                }
                return current;
            }
            catch { return p; }
        });
    }
}
