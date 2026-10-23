using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Windows;
using FirewallFamiliar.Core;
using FirewallFamiliar.Models;
using FirewallFamiliar.Views;

namespace FirewallFamiliar;

/// <summary>
/// Parte de la ventana principal que vigila: programas sospechosos, escaneos de puertos
/// y registros guardados en disco.
/// </summary>
public partial class MainWindow
{
    private readonly ScanDetector _scan = new();
    private readonly HashSet<string> _alertedSuspicious = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastTrafficLog = new();
    private int _attemptsThisSecond, _scansThisSecond;
    private int _attemptsTotal, _scansTotal;
    private LogViewerWindow? _logViewer;

    /// <summary>
    /// Programas de los que ya se avisó en los últimos 7 días: no se repite el aviso cada vez
    /// que se abre Firewall Familiar (siguen marcados en naranja en la lista).
    /// </summary>
    private void LoadPreviousAlerts()
    {
        try
        {
            for (int d = 0; d < 7; d++)
                foreach (var e in LogStore.Read(LogKind.Seguridad, DateTime.Today.AddDays(-d)))
                    if (e.Outcome == "Sospechoso" && !string.IsNullOrEmpty(e.App)) _alertedSuspicious.Add(e.App);
        }
        catch { }
    }

    private void InitSecurity()
    {
        _firewall.ForeignInboundBlocked += c => Dispatcher.BeginInvoke(() => OnInboundAttempt(c));
        LogStore.Error += msg => Dispatcher.BeginInvoke(() => Log("⚠ " + msg));
        UpdateAttackStatus();
    }

    // =====================================================================
    // Programas sospechosos
    // =====================================================================

    /// <summary>
    /// Mira si un programa parece sospechoso: oculto y sin firma, oculto y metido en una carpeta
    /// rara (temporales, Descargas...), o con una firma que no es válida. Avisa una vez por programa.
    /// </summary>
    private void CheckSuspicious(AppRow row)
    {
        if (row.Path.Length == 0 || row.Path == "System") { row.Suspicious = ""; return; }
        var sig = row.Signature;
        if (sig.Status == SignatureStatus.Pendiente) return; // se decidirá cuando termine la comprobación

        var reasons = new List<string>();
        if (sig.Status == SignatureStatus.NoValida) reasons.Add("su firma digital NO es válida (" + sig.Detail + ")");
        if (row.Kind == ProcessKind.Oculto)
        {
            if (sig.Status == SignatureStatus.SinFirma) reasons.Add("funciona oculto y no tiene firma digital");
            if (Suspicion.OddFolder(row.Path) is { } folder) reasons.Add("funciona oculto desde " + folder);
        }

        row.Suspicious = string.Join("; ", reasons);
        if (reasons.Count == 0 || !_alertedSuspicious.Add(row.Path)) return;
        // Si ya lo has bloqueado, no hace falta volver a avisar
        if (_rules.ActionFor(row.Path) == RuleAction.Bloquear) return;

        Log(new ConsoleEvent
        {
            Text = $"⚠ PROGRAMA SOSPECHOSO: {row.Name} (PID {row.Pid}): {row.Suspicious}. Pincha para ver qué es.",
            AppPath = row.Path, Pid = row.Pid, Outcome = "Sospechoso"
        });
    }


    // =====================================================================
    // Intentos de entrada y escaneos de puertos
    // =====================================================================

    /// <summary>Alguien de fuera ha intentado entrar y otro filtro (Firewall de Windows) lo ha parado.</summary>
    private void OnInboundAttempt(BlockedConnection c)
    {
        _attemptsThisSecond++;
        _attemptsTotal++;
        _blockedInThisSecond++;
        LogTrafficBlock(c);
        CheckScan(c);
        UpdateAttackStatus();
    }

    private void CheckScan(BlockedConnection c)
    {
        if (c.RemoteAddress == null || c.LocalPort == 0) return;
        int ports = _scan.Add(c.RemoteAddress, c.RemotePort, c.LocalPort, DateTime.Now);
        if (ports == 0) return;

        _scansThisSecond++;
        _scansTotal++;
        var list = _scan.PortsFrom(c.RemoteAddress);
        string sample = string.Join(", ", list.Take(12)) + (list.Count > 12 ? "..." : "");
        string where = IpInfo.Special(c.RemoteAddress) != null ? " (de tu red de casa)" : "";
        Log(new ConsoleEvent
        {
            Text = $"⚠ POSIBLE ATAQUE: {c.RemoteAddress}{where} ha probado {ports} puertos distintos en menos de un minuto ({sample}). Bloqueado.",
            RemoteAddress = c.RemoteAddress, RemotePort = c.RemotePort, Protocol = c.Protocol, Inbound = true, Outcome = "Escaneo"
        });
        UpdateAttackStatus();
    }

    private void UpdateAttackStatus()
    {
        StatusAttacks.Text = $"Intentos de entrada bloqueados: {_attemptsTotal}   Escaneos: {_scansTotal}";
        StatusAttacks.Foreground = _scansTotal > 0 ? System.Windows.Media.Brushes.Red : System.Windows.Media.Brushes.Black;
    }

    // =====================================================================
    // Registros en disco
    // =====================================================================

    /// <summary>Anota en el registro de tráfico un intento bloqueado (sin repetir el mismo en 10 s).</summary>
    private void LogTrafficBlock(BlockedConnection c)
    {
        string key = $"{c.AppPath}|{c.RemoteAddress}|{c.RemotePort}|{c.LocalPort}|{c.Inbound}";
        if (_lastTrafficLog.TryGetValue(key, out var last) && c.Time - last < TimeSpan.FromSeconds(10)) return;
        _lastTrafficLog[key] = c.Time;
        if (_lastTrafficLog.Count > 5000)
            foreach (var k in _lastTrafficLog.Where(kv => c.Time - kv.Value > TimeSpan.FromSeconds(10)).Select(kv => kv.Key).ToList())
                _lastTrafficLog.Remove(k);

        string name = c.AppPath.Length == 0 ? "" : ProcessMonitor.FileName(c.AppPath) + " ";
        LogStore.Write(LogKind.Trafico, new LogEntry
        {
            Time = c.Time,
            Text = c.Inbound
                ? $"Entrada bloqueada {name}desde {c.Remote} al puerto {c.LocalPort} ({c.Reason})"
                : $"Salida bloqueada: {name}hacia {c.Remote} ({c.Reason})",
            App = c.AppPath.Length > 0 ? c.AppPath : null,
            Remote = c.RemoteAddress?.ToString(), RemotePort = c.RemotePort, LocalPort = c.LocalPort,
            Protocol = c.Protocol, Inbound = c.Inbound, Outcome = "Bloqueado"
        });
    }

    /// <summary>Anota en el registro de tráfico una conexión nueva que se ha abierto.</summary>
    private void LogTrafficConnection(ConnectionInfo c, AppRow? app, bool inbound)
    {
        IPAddress.TryParse(c.RemoteAddress, out var ip);
        if (ip == null || IPAddress.IsLoopback(ip)) return;
        string name = app?.Name ?? (c.Pid == 0 ? "Sistema" : $"PID {c.Pid}");
        LogStore.Write(LogKind.Trafico, new LogEntry
        {
            Time = DateTime.Now,
            Text = inbound ? $"{name}: conexión entrante desde {c.Remote}" : $"{name}: conexión con {c.Remote}",
            App = string.IsNullOrEmpty(app?.Path) ? null : app!.Path,
            Pid = c.Pid, Remote = ip.ToString(), RemotePort = c.RemotePort, LocalPort = c.LocalPort,
            Protocol = c.Protocol.Replace("v6", ""), Inbound = inbound, Outcome = "Permitido"
        });
    }

    private void OnShowLogs(object sender, RoutedEventArgs e)
    {
        if (_logViewer != null)
        {
            if (_logViewer.WindowState == WindowState.Minimized) _logViewer.WindowState = WindowState.Normal;
            _logViewer.Activate();
            return;
        }
        _logViewer = new LogViewerWindow(ShowDetails, ReportSnapshot) { Owner = this };
        _logViewer.Closed += (_, _) => _logViewer = null;
        _logViewer.Show();
    }

    /// <summary>Copia de las reglas y de los programas en ejecución, para el informe de análisis.</summary>
    private (RuleSet, IReadOnlyList<ProcessSummary>) ReportSnapshot()
    {
        var procs = _apps.Select(a => new ProcessSummary(a.Name, a.Pid, a.Path, a.KindText, a.SeverityText, a.SignatureText,
            a.RuleText, a.Memory, a.Connections, a.Listening, a.BytesIn, a.BytesOut, a.Suspicious)).ToList();
        var json = System.Text.Json.JsonSerializer.Serialize(_rules);
        return (System.Text.Json.JsonSerializer.Deserialize<RuleSet>(json)!, procs);
    }

    private void OnOpenLogsFolder(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(LogStore.Folder);
        System.Diagnostics.Process.Start("explorer.exe", $"\"{LogStore.Folder}\"");
    }
}
