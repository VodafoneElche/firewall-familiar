using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace FirewallFamiliar.Core;

/// <summary>
/// Registros propios del agente de Trend Micro (Worry-Free / Client Server Security Agent), que casi
/// no escribe en los registros de Windows. Se leen sus archivos de texto: virus, spyware, comportamiento
/// sospechoso, webs bloqueadas, informes de análisis y conexión con su nube.
/// </summary>
public static class TrendLogs
{
    private static readonly string[] AgentDirs =
    {
        @"C:\Program Files (x86)\Trend Micro\Client Server Security Agent",
        @"C:\Program Files\Trend Micro\Client Server Security Agent",
        @"C:\Program Files (x86)\Trend Micro\OfficeScan Client",
        @"C:\Program Files\Trend Micro\OfficeScan Client",
        @"C:\Program Files (x86)\Trend Micro\Security Agent",
        @"C:\Program Files\Trend Micro\Security Agent"
    };

    /// <summary>Archivo (dentro de la carpeta del agente) → qué es. Los marcados como urgentes avisan al momento.</summary>
    public static readonly (string File, string What, bool Urgent)[] Logs =
    {
        (@"Misc\pccnt35.log", "Virus y malware detectados", true),
        (@"Misc\spyware.log", "Spyware / grayware detectado", true),
        (@"Misc\AEGIS.log", "Comportamiento sospechoso bloqueado", true),
        (@"Misc\AEGIS_BM.log", "Vigilancia de comportamiento", false),
        (@"Misc\OfcUrlf.log", "Webs bloqueadas (reputación web)", false),
        (@"Misc\OfcUrlCategory.log", "Webs bloqueadas por categoría", false),
    };

    public static string? AgentDir => AgentDirs.FirstOrDefault(Directory.Exists);

    public static string Section(DateTime from, DateTime to)
    {
        var dir = AgentDir;
        var sb = new StringBuilder();
        sb.AppendLine("### Registros propios de Trend Micro");
        sb.AppendLine();
        if (dir == null) { sb.AppendLine("No hay agente de Trend Micro en este PC."); sb.AppendLine(); return sb.ToString(); }

        foreach (var (file, what, _) in Logs)
        {
            var path = Path.Combine(dir, file);
            if (!File.Exists(path)) continue;
            var lines = ReadLines(path);
            sb.AppendLine($"- **{what}** (`{file}`): {(lines.Count == 0 ? "vacío ✔" : $"{lines.Count} líneas, últimas:")}");
            foreach (var l in lines.TakeLast(40)) sb.AppendLine("    " + l);
        }

        // Informes de análisis y conexiones con la nube de Trend, de cada día del periodo
        for (var d = from.Date; d <= to.Date; d = d.AddDays(1))
        {
            foreach (var (file, what) in new[] { ($@"report\{d:yyyyMMdd}.log", "Análisis del antivirus"), ($@"ConnLog\Conn_{d:yyyyMMdd}.log", "Conexión con la consola de Trend") })
            {
                var path = Path.Combine(dir, file);
                if (!File.Exists(path)) continue;
                var lines = ReadLines(path);
                sb.AppendLine($"- **{what} {d:dd/MM}** (`{file}`): {lines.Count} líneas");
                foreach (var l in lines.TakeLast(30)) sb.AppendLine("    " + l);
            }
        }
        sb.AppendLine();
        return sb.ToString();
    }

    /// <summary>Tamaño actual de los registros urgentes (para ver si crecen).</summary>
    public static Dictionary<string, long> UrgentSizes()
    {
        var sizes = new Dictionary<string, long>();
        var dir = AgentDir;
        if (dir == null) return sizes;
        foreach (var (file, _, urgent) in Logs)
        {
            if (!urgent) continue;
            var p = Path.Combine(dir, file);
            try { sizes[p] = File.Exists(p) ? new FileInfo(p).Length : 0; } catch { }
        }
        return sizes;
    }

    /// <summary>Líneas nuevas de un registro desde <paramref name="fromByte"/>.</summary>
    public static List<string> NewLines(string path, long fromByte)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fromByte > fs.Length) fromByte = 0; // el archivo se ha vaciado y vuelto a escribir
            fs.Seek(fromByte, SeekOrigin.Begin);
            var bytes = new byte[Math.Min(fs.Length - fromByte, 64 * 1024)];
            int n = fs.Read(bytes, 0, bytes.Length);
            return Split(Decode(bytes.AsSpan(0, n).ToArray()));
        }
        catch { return new List<string>(); }
    }

    public static string WhatIs(string path) =>
        Logs.FirstOrDefault(l => path.EndsWith(l.File, StringComparison.OrdinalIgnoreCase)).What ?? Path.GetFileName(path);

    private static List<string> ReadLines(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            long start = Math.Max(0, fs.Length - 256 * 1024); // como mucho lo último (256 KB)
            fs.Seek(start, SeekOrigin.Begin);
            var bytes = new byte[fs.Length - start];
            int n = fs.Read(bytes, 0, bytes.Length);
            return Split(Decode(bytes.AsSpan(0, n).ToArray()));
        }
        catch (Exception ex) { return new List<string> { "(no se pudo leer: " + ex.Message + ")" }; }
    }

    private static string Decode(byte[] b)
    {
        // Trend usa a veces UTF-16 (con muchos ceros) y a veces texto normal
        int zeros = b.Take(400).Count(x => x == 0);
        if (b.Length > 1 && zeros > Math.Min(b.Length, 400) / 4) return Encoding.Unicode.GetString(b);
        return Encoding.UTF8.GetString(b);
    }

    private static List<string> Split(string text) =>
        text.Split('\n')
            .Select(l => new string(l.Select(c => c == '\t' ? ' ' : char.IsControl(c) ? ' ' : c).ToArray()).Replace("<;>", " · ").Trim())
            .Where(l => l.Length > 0)
            .Select(l => l.Length > 300 ? l[..300] + "..." : l)
            .ToList();
}
