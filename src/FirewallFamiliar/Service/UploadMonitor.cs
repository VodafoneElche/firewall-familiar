using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using FirewallFamiliar.Core;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace FirewallFamiliar.Service;

/// <summary>
/// Cuenta cuántos datos SUBE cada programa a Internet (lo que sale del PC), con los eventos de red
/// de Windows. Usa su propia sesión de eventos, así no choca con la ventana completa.
/// Cada 5 minutos se mira la última hora: una subida muy grande puede ser alguien llevándose
/// fotos o documentos.
/// </summary>
internal sealed class UploadMonitor : IDisposable
{
    private const string SessionName = "FirewallFamiliar-Subidas";
    private static readonly Guid KernelNetwork = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private static readonly HashSet<int> SendEvents = new() { 10, 26, 42, 58 }; // TCP y UDP, IPv4 e IPv6

    private const long InfoBytes = 200L * 1024 * 1024;     // se anota en el registro
    private const long AlertBytes = 1024L * 1024 * 1024;   // aviso urgente
    private const long SuspiciousAlertBytes = 50L * 1024 * 1024; // aviso urgente si el programa es sospechoso

    /// <summary>Programas que suben mucho porque es su trabajo (copias y nubes): solo se anotan.</summary>
    private static readonly string[] SyncApps =
    {
        "onedrive", "googledrivefs", "dropbox", "megasync", "icloud", "backup", "boxsync", "box.exe", "pcloud",
        "synology", "nextcloud", "owncloud", "acronis", "veeam", "macrium", "steam", "obs64", "zoom", "teams"
    };

    private readonly object _lock = new();
    private readonly Dictionary<int, Dictionary<string, long>> _current = new(); // PID → IP → bytes en los 5 min actuales
    private readonly Queue<Dictionary<string, Dictionary<string, long>>> _buckets = new(); // ruta → IP → bytes, por cada 5 min
    private readonly Dictionary<string, DateTime> _lastNote = new(StringComparer.OrdinalIgnoreCase);
    private readonly Func<int, string> _pathOf;
    private readonly Action<string, string, string?, string?> _log; // texto, resultado, ruta, ip
    private TraceEventSession? _session;

    public UploadMonitor(Func<int, string> pathOf, Action<string, string, string?, string?> log)
    {
        _pathOf = pathOf;
        _log = log;
    }

    public string? Start()
    {
        try
        {
            try { TraceEventSession.GetActiveSession(SessionName)?.Stop(true); } catch { }
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session.EnableProvider(KernelNetwork, TraceEventLevel.Informational, 0x30 /* IPv4 + IPv6 */);
            var parser = new RegisteredTraceEventParser(_session.Source);
            parser.All += OnEvent;
            Task.Run(() => { try { _session.Source.Process(); } catch { } });
            return null;
        }
        catch (Exception ex) { return ex.Message; }
    }

    private void OnEvent(TraceEvent e)
    {
        if (!SendEvents.Contains((int)e.ID)) return;
        try
        {
            int pid = Convert.ToInt32(e.PayloadByName("PID") ?? e.ProcessID);
            long size = Convert.ToInt64(e.PayloadByName("size") ?? 0);
            string ip = e.PayloadByName("daddr")?.ToString() ?? "";
            if (size <= 0 || pid <= 4) return;
            if (IPAddress.TryParse(ip, out var a) && IpInfo.Special(a) != null) return; // solo lo que va a Internet
            lock (_lock)
            {
                if (!_current.TryGetValue(pid, out var byIp)) _current[pid] = byIp = new Dictionary<string, long>();
                byIp[ip] = byIp.GetValueOrDefault(ip) + size;
            }
        }
        catch { }
    }

    /// <summary>Cada 5 minutos: cierra el tramo y revisa la última hora.</summary>
    public void Check()
    {
        Dictionary<int, Dictionary<string, long>> slice;
        lock (_lock)
        {
            slice = new Dictionary<int, Dictionary<string, long>>(_current);
            _current.Clear();
        }
        var byPath = new Dictionary<string, Dictionary<string, long>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (pid, ips) in slice)
        {
            string path = _pathOf(pid);
            if (path.Length == 0) path = $"PID {pid}";
            if (!byPath.TryGetValue(path, out var d)) byPath[path] = d = new Dictionary<string, long>();
            foreach (var (ip, b) in ips) d[ip] = d.GetValueOrDefault(ip) + b;
        }
        _buckets.Enqueue(byPath);
        while (_buckets.Count > 12) _buckets.Dequeue();

        // Total de la última hora por programa
        var hour = new Dictionary<string, Dictionary<string, long>>(StringComparer.OrdinalIgnoreCase);
        foreach (var b in _buckets)
            foreach (var (path, ips) in b)
            {
                if (!hour.TryGetValue(path, out var d)) hour[path] = d = new Dictionary<string, long>();
                foreach (var (ip, n) in ips) d[ip] = d.GetValueOrDefault(ip) + n;
            }

        foreach (var (path, ips) in hour)
        {
            long total = ips.Values.Sum();
            if (total < SuspiciousAlertBytes) continue;
            bool windows = path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase);
            bool sync = SyncApps.Any(s => path.Contains(s, StringComparison.OrdinalIgnoreCase));
            bool suspicious = !windows && path.Contains('\\') && IsSuspicious(path);
            string name = path.Contains('\\') ? ProcessMonitor.FileName(path) : path;
            var top = ips.OrderByDescending(kv => kv.Value).Take(3).ToList();
            string where = string.Join(", ", top.Select(kv => $"{kv.Key} ({Mb(kv.Value)})"));
            string ip = top[0].Key;

            if ((suspicious && total >= SuspiciousAlertBytes) || (!sync && !windows && total >= AlertBytes))
            {
                if (Due("alerta|" + path, TimeSpan.FromHours(6)))
                    _log($"⚠ SUBIDA GRANDE: {name} ha enviado {Mb(total)} a Internet en la última hora" +
                         $"{(suspicious ? " y es un programa sin firma o en una carpeta rara" : "")}. Destinos: {where}. " +
                         "Puede ser alguien llevándose archivos del PC.", "Alerta", path.Contains('\\') ? path : null, ip);
            }
            else if (total >= InfoBytes && Due("info|" + path, TimeSpan.FromHours(1)))
                _log($"Subida grande: {name} ha enviado {Mb(total)} a Internet en la última hora. Destinos: {where}.",
                    "Subida", path.Contains('\\') ? path : null, ip);
        }
    }

    private static bool IsSuspicious(string path)
    {
        var sig = Signature.Get(path);
        return sig.Status == SignatureStatus.NoValida ||
               (sig.Status == SignatureStatus.SinFirma && Suspicion.OddFolder(path) != null);
    }

    private bool Due(string key, TimeSpan every)
    {
        if (_lastNote.TryGetValue(key, out var t) && DateTime.Now - t < every) return false;
        _lastNote[key] = DateTime.Now;
        return true;
    }

    private static string Mb(long b) => b >= 1024L * 1024 * 1024 ? $"{b / 1024.0 / 1024 / 1024:0.0} GB" : $"{b / 1024.0 / 1024:0} MB";

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
