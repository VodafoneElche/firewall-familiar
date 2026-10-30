using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Management;
using System.Text;

namespace FirewallFamiliar.Core;

/// <summary>
/// Lo que dicen los antivirus del PC, para el informe: qué antivirus tiene Windows registrados
/// (Trend Micro, Defender...) y si están activos y al día, y los eventos que han dejado en los
/// registros de Windows (detecciones, análisis, errores).
/// </summary>
public static class AntivirusInfo
{
    /// <summary>Nombres de origen de eventos de antivirus (Trend Micro y Microsoft Defender).</summary>
    private static readonly string[] Providers =
    {
        "trend", "officescan", "apex one", "worry-free", "tmbmsrv", "ntrtscan", "pccnt", "tmlisten", "tmccsf", "tmpfw",
        "tmcpm", "amsp", "deep security", "windows defender", "microsoft antimalware", "securitycenter"
    };

    /// <summary>Eventos de Defender que son detecciones de virus.</summary>
    public static readonly HashSet<int> DefenderDetections = new() { 1006, 1007, 1015, 1116, 1117, 1118, 1119 };

    private const int MaxEvents = 300;

    public static string Section(DateTime from, DateTime to)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## 9. Antivirus (Trend Micro, Defender...)");
        sb.AppendLine();
        try { Products(sb); } catch (Exception ex) { sb.AppendLine("- No se pudo consultar el Centro de seguridad: " + ex.Message); }
        sb.AppendLine();

        var events = new List<(DateTime Time, string Log, string Source, int Id, string Level, string Text)>();
        string? error = null;
        foreach (var log in new[] { "Application", "System", "Microsoft-Windows-Windows Defender/Operational" })
        {
            try { events.AddRange(Read(log, from, to.AddDays(1))); }
            catch (Exception ex) { error ??= $"{log}: {ex.Message}"; }
        }
        events = events.OrderBy(e => e.Time).ToList();
        var detections = events.Where(IsDetection).ToList();
        sb.AppendLine($"Eventos de antivirus en los registros de Windows: {events.Count}. Posibles detecciones de virus: {detections.Count}.");
        if (error != null) sb.AppendLine($"(No se pudo leer algún registro: {error})");
        sb.AppendLine();
        if (events.Count > 0)
        {
            sb.AppendLine("| Hora | Origen | Id | Nivel | Mensaje |");
            sb.AppendLine("|---|---|---|---|---|");
            // Primero lo importante (detecciones, errores y avisos); los informativos solo si cabe
            var shown = events.Where(e => IsDetection(e) || e.Level != "Información").Take(MaxEvents).ToList();
            shown.AddRange(events.Where(e => !shown.Contains(e)).Take(Math.Max(0, MaxEvents - shown.Count)));
            foreach (var e in shown.OrderBy(e => e.Time))
                sb.AppendLine($"| {e.Time:dd/MM HH:mm:ss} | {Cell(e.Source)} | {e.Id} | {(IsDetection(e) ? "⚠ DETECCIÓN" : e.Level)} | {Cell(e.Text)} |");
            if (events.Count > shown.Count) sb.AppendLine($"\n({events.Count - shown.Count} eventos informativos más no se muestran.)");
        }
        sb.AppendLine();
        try { sb.Append(TrendLogs.Section(from, to)); }
        catch (Exception ex) { sb.AppendLine("Registros de Trend Micro: no se pudieron leer (" + ex.Message + ")."); sb.AppendLine(); }
        return sb.ToString();
    }

    /// <summary>Detecciones de virus nuevas desde <paramref name="since"/> (para avisar al momento).</summary>
    public static List<(DateTime Time, string Source, string Text)> DetectionsSince(DateTime since)
    {
        var found = new List<(DateTime, string, string)>();
        foreach (var log in new[] { "Application", "Microsoft-Windows-Windows Defender/Operational" })
        {
            try
            {
                foreach (var e in Read(log, since.AddSeconds(1), DateTime.Now.AddMinutes(1)))
                    if (IsDetection(e)) found.Add((e.Item1, e.Item3, e.Item6));
            }
            catch { }
        }
        return found.OrderBy(f => f.Item1).ToList();
    }

    private static bool IsDetection((DateTime Time, string Log, string Source, int Id, string Level, string Text) e) =>
        (e.Source.Contains("Defender", StringComparison.OrdinalIgnoreCase) && DefenderDetections.Contains(e.Id)) ||
        (!e.Source.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
         (e.Text.Contains("virus", StringComparison.OrdinalIgnoreCase) || e.Text.Contains("malware", StringComparison.OrdinalIgnoreCase) ||
          e.Text.Contains("amenaza", StringComparison.OrdinalIgnoreCase) || e.Text.Contains("threat", StringComparison.OrdinalIgnoreCase) ||
          e.Text.Contains("spyware", StringComparison.OrdinalIgnoreCase) || e.Text.Contains("ransomware", StringComparison.OrdinalIgnoreCase)) &&
         e.Level != "Información");

    private static IEnumerable<(DateTime, string, string, int, string, string)> Read(string log, DateTime from, DateTime until)
    {
        string query = $"*[System[TimeCreated[@SystemTime>='{from.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.000Z}' and @SystemTime<'{until.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.000Z}']]]";
        using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, query));
        var list = new List<(DateTime, string, string, int, string, string)>();
        for (EventRecord? r = reader.ReadEvent(); r != null; r = reader.ReadEvent())
            using (r)
            {
                string source = r.ProviderName ?? "";
                if (!log.Contains("Defender") && !Providers.Any(p => source.Contains(p, StringComparison.OrdinalIgnoreCase))) continue;
                string text;
                try { text = r.FormatDescription() ?? ""; } catch { text = ""; }
                if (text.Length == 0)
                    try { text = string.Join(" · ", r.Properties.Select(p => p.Value?.ToString()).Where(v => !string.IsNullOrWhiteSpace(v))); } catch { }
                if (text.Length > 400) text = text[..400] + "...";
                string level = r.Level switch { 1 => "Crítico", 2 => "Error", 3 => "Aviso", _ => "Información" };
                list.Add((r.TimeCreated ?? from, log, source, r.Id, level, text));
                if (list.Count > 5000) break;
            }
        return list;
    }

    /// <summary>Antivirus registrados en el Centro de seguridad de Windows.</summary>
    private static void Products(StringBuilder sb)
    {
        using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName, productState, timestamp FROM AntiVirusProduct");
        int n = 0;
        foreach (ManagementObject mo in searcher.Get())
            using (mo)
            {
                n++;
                uint state = Convert.ToUInt32(mo["productState"] ?? 0u);
                // productState: byte 2 = activado (0x10 = sí); byte 3 = firmas (0x00 = al día, 0x10 = antiguas)
                bool on = ((state >> 8) & 0xFF) is 0x10 or 0x11;
                bool upToDate = (state & 0xFF) == 0x00;
                sb.AppendLine($"- {mo["displayName"]}: {(on ? "ACTIVO" : "desactivado")}, firmas {(upToDate ? "al día" : "ANTIGUAS")}  (estado 0x{state:X6}, último cambio {mo["timestamp"]})");
            }
        if (n == 0) sb.AppendLine("- Windows no tiene ningún antivirus registrado.");
    }

    /// <summary>Antivirus registrados en Windows y si están activos y al día.</summary>
    public static List<(string Name, bool On, bool UpToDate)> ProductList()
    {
        var list = new List<(string, bool, bool)>();
        using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
        foreach (ManagementObject mo in searcher.Get())
            using (mo)
            {
                uint state = Convert.ToUInt32(mo["productState"] ?? 0u);
                list.Add((mo["displayName"]?.ToString() ?? "", ((state >> 8) & 0xFF) is 0x10 or 0x11, (state & 0xFF) == 0x00));
            }
        return list;
    }

    private static string Cell(string s) => s.Replace("|", "/").Replace("\r", " ").Replace("\n", " ").Trim();
}
