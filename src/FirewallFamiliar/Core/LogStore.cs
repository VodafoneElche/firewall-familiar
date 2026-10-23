using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace FirewallFamiliar.Core;

public enum LogKind
{
    /// <summary>Avisos, bloqueos, respuestas, cambios de reglas... (lo mismo que la consola).</summary>
    Seguridad,
    /// <summary>Cada conexión nueva y cada intento bloqueado.</summary>
    Trafico
}

/// <summary>Una línea de un registro guardado en disco.</summary>
public sealed class LogEntry
{
    public DateTime Time { get; set; }
    public string Text { get; set; } = "";
    public string? App { get; set; }
    public int Pid { get; set; }
    public string? Remote { get; set; }
    public int RemotePort { get; set; }
    public int LocalPort { get; set; }
    public string Protocol { get; set; } = "";
    public bool Inbound { get; set; }
    public string Outcome { get; set; } = "";

    [JsonIgnore] public string TimeText => Time.ToString("HH:mm:ss");
    [JsonIgnore] public string AppName => string.IsNullOrEmpty(App) ? "" : Path.GetFileName(App);
    [JsonIgnore] public string DirectionText => Remote == null ? "" : Inbound ? "↓ Entrante" : "↑ Saliente";
    [JsonIgnore] public string RemoteText => Remote == null ? "" : RemotePort > 0 ? $"{Remote}:{RemotePort}" : Remote;
    [JsonIgnore] public string PortMeaning => Ports.Describe(Inbound ? LocalPort : RemotePort, Protocol);

    public static LogEntry From(ConsoleEvent e) => new()
    {
        Time = e.Time, Text = e.Text, App = e.AppPath, Pid = e.Pid, Remote = e.RemoteAddress?.ToString(),
        RemotePort = e.RemotePort, Protocol = e.Protocol, Inbound = e.Inbound, Outcome = e.Outcome
    };

    public ConsoleEvent ToEvent() => new()
    {
        Time = Time, Text = Text, AppPath = string.IsNullOrEmpty(App) ? null : App, Pid = Pid,
        RemoteAddress = IPAddress.TryParse(Remote, out var ip) ? ip : null,
        RemotePort = RemotePort, Protocol = Protocol, Inbound = Inbound, Outcome = Outcome
    };
}

/// <summary>
/// Guarda los registros en C:\ProgramData\FirewallFamiliar\registros, un archivo por día
/// y tipo (una línea JSON por evento). Se borran solos los de más de 30 días.
/// </summary>
public static class LogStore
{
    public static readonly string Folder = Path.Combine(RuleStore.Folder, "registros");
    public const int KeepDays = 30;
    private const long MaxFileBytes = 100L * 1024 * 1024; // por si algo se vuelve loco

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly BlockingCollection<(LogKind Kind, LogEntry Entry)> Queue = new(10000);
    private static int _started;

    /// <summary>Último error al escribir (para avisar una sola vez).</summary>
    public static event Action<string>? Error;

    public static void Write(LogKind kind, LogEntry entry)
    {
        if (Interlocked.Exchange(ref _started, 1) == 0) Start();
        Queue.TryAdd((kind, entry)); // si la cola está llena se pierde la línea, nunca se bloquea la ventana
    }

    private static string FilePath(LogKind kind, DateTime day) =>
        Path.Combine(Folder, $"{(kind == LogKind.Seguridad ? "seguridad" : "trafico")}-{day:yyyy-MM-dd}.jsonl");

    private static void Start()
    {
        var t = new Thread(() =>
        {
            Prune();
            bool reported = false;
            DateTime lastDay = DateTime.Today;
            foreach (var (kind, entry) in Queue.GetConsumingEnumerable())
            {
                if (entry.Time.Date != lastDay) { lastDay = entry.Time.Date; Prune(); } // cambio de día
                try
                {
                    Directory.CreateDirectory(Folder);
                    string path = FilePath(kind, entry.Time);
                    var info = new FileInfo(path);
                    if (info.Exists && info.Length > MaxFileBytes) continue;
                    var sb = new StringBuilder(JsonSerializer.Serialize(entry, Json)).Append('\n');
                    // Se juntan las líneas que esperan, para escribir de una vez
                    while (Queue.TryTake(out var more))
                    {
                        if (more.Kind == kind && more.Entry.Time.Date == entry.Time.Date)
                            sb.Append(JsonSerializer.Serialize(more.Entry, Json)).Append('\n');
                        else
                        {
                            File.AppendAllText(FilePath(more.Kind, more.Entry.Time), JsonSerializer.Serialize(more.Entry, Json) + "\n");
                        }
                    }
                    File.AppendAllText(path, sb.ToString());
                }
                catch (Exception ex)
                {
                    if (!reported) { reported = true; Error?.Invoke("No se pueden guardar los registros: " + ex.Message); }
                }
            }
        })
        { IsBackground = true, Name = "Registros", Priority = ThreadPriority.BelowNormal };
        t.Start();
    }

    private static void Prune()
    {
        try
        {
            if (!Directory.Exists(Folder)) return;
            var limit = DateTime.Today.AddDays(-KeepDays);
            foreach (var f in Directory.EnumerateFiles(Folder, "*.jsonl"))
                if (DayOf(f) is { } d && d < limit) File.Delete(f);
        }
        catch { }
    }

    private static DateTime? DayOf(string file)
    {
        string name = Path.GetFileNameWithoutExtension(file);
        int dash = name.IndexOf('-');
        return dash > 0 && DateTime.TryParseExact(name[(dash + 1)..], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
            ? d : null;
    }

    /// <summary>Días que tienen registro de ese tipo, del más reciente al más antiguo.</summary>
    public static List<DateTime> Days(LogKind kind)
    {
        string prefix = kind == LogKind.Seguridad ? "seguridad-" : "trafico-";
        try
        {
            if (!Directory.Exists(Folder)) return new();
            return Directory.EnumerateFiles(Folder, prefix + "*.jsonl")
                .Select(DayOf).Where(d => d != null).Select(d => d!.Value)
                .OrderByDescending(d => d).ToList();
        }
        catch { return new(); }
    }

    /// <summary>Lee un día entero. Las líneas estropeadas se saltan.</summary>
    public static List<LogEntry> Read(LogKind kind, DateTime day)
    {
        var list = new List<LogEntry>();
        string path = FilePath(kind, day);
        if (!File.Exists(path)) return list;
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(fs, Encoding.UTF8);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length == 0) continue;
            try { if (JsonSerializer.Deserialize<LogEntry>(line, Json) is { } e) list.Add(e); }
            catch { }
        }
        return list;
    }
}
