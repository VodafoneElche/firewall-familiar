using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace FirewallFamiliar.Core;

/// <summary>Datos de un programa a partir de su archivo .exe.</summary>
public sealed record FileInfoDetails(string Description, string Company, string Product, string Version, string Signer, DateTime? Modified);

public static class FileDetails
{
    private static readonly ConcurrentDictionary<string, string> CaseCache = new(StringComparer.OrdinalIgnoreCase);

    public static FileInfoDetails Read(string path)
    {
        string desc = "", company = "", product = "", version = "", signer = "";
        DateTime? modified = null;
        if (string.Equals(path, "System", StringComparison.OrdinalIgnoreCase))
            return new FileInfoDetails("Núcleo de Windows", "Microsoft Corporation", "Windows", "", "Microsoft Windows", null);
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
        signer = ReadSigner(path);
        return new FileInfoDetails(desc, company, product, version, signer, modified);
    }

    /// <summary>
    /// Nombre de quien firmó el archivo (por ejemplo "Google LLC"), o "" si no lleva firma propia.
    /// Muchos archivos de Windows van firmados en un catálogo aparte y aquí salen sin firma.
    /// </summary>
    private static string ReadSigner(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrEmpty(cn) ? cert.Subject : cn;
        }
        catch
        {
            return "";
        }
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
