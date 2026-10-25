using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Service;

/// <summary>
/// La parte del servicio que alimenta el SOC familiar:
///  - cada minuto manda los avisos importantes nuevos del registro de seguridad
///    (sean del servicio o de la ventana completa);
///  - cada 15 minutos manda un "latido" para que el buzón sepa que este PC sigue protegido;
///  - una vez al día sube el informe completo del día anterior;
///  - al apagar, suspender o parar la protección se despide, y así un silencio sin
///    despedida se puede tomar como algo raro.
/// Si no hay Internet, lo pendiente se manda en cuanto vuelva.
/// </summary>
internal sealed class SocReporter
{
    /// <summary>Lo que se avisa al momento (por correo desde el buzón).</summary>
    public static readonly HashSet<string> UrgentOutcomes = new() { "Escaneo", "Sospechoso", "AccesoRemoto", "Alerta" };

    private static readonly string StateFile = Path.Combine(RuleStore.Folder, "soc-estado.json");
    private static readonly TimeSpan BeatEvery = TimeSpan.FromMinutes(15);
    private const int MaxReportDaysBack = 7;

    private readonly Action<string> _log;
    private readonly Func<object> _status;
    private readonly SemaphoreSlim _busy = new(1, 1);
    private State _state;
    private DateTime _lastBeat = DateTime.MinValue;
    private DateTime _beatNotBefore = DateTime.MinValue;
    private DateTime _lastScreenEvent = DateTime.MinValue;
    private DateTime _lastAlertFileWrite = DateTime.MinValue;
    private string? _lastError;
    private Timer? _timer;

    private sealed class State
    {
        public DateTime LastAlert { get; set; }
        public DateTime LastReportDay { get; set; }
    }

    public SocReporter(Action<string> log, Func<object> status)
    {
        _log = log;
        _status = status;
        _state = LoadState();
    }

    public void Start() => _timer = new Timer(_ => _ = TickAsync(), null, TimeSpan.FromSeconds(20), TimeSpan.FromMinutes(1));

    public void Stop() => _timer?.Dispose();

    /// <summary>El PC vuelve de la suspensión: latido en cuanto haya red.</summary>
    public void OnResume() { _lastBeat = DateTime.MinValue; _beatNotBefore = DateTime.MinValue; }

    /// <summary>
    /// Pantalla o tapa: Windows no dice si se enciende o se apaga. Por si es que se va a dormir
    /// (tapa cerrada en un portátil moderno, que no avisa de suspensión), se despide ya; y al
    /// minuto y medio manda un latido. Si el PC sigue despierto el latido llega y vuelve a "activo";
    /// si se ha dormido, no llega y el buzón no da la alarma de silencio.
    /// </summary>
    public void OnScreenOrLid()
    {
        if (DateTime.Now - _lastScreenEvent < TimeSpan.FromMinutes(2)) return;
        _lastScreenEvent = DateTime.Now;
        _beatNotBefore = DateTime.Now.AddSeconds(90);
        _lastBeat = DateTime.MinValue;
        System.Threading.ThreadPool.QueueUserWorkItem(_ => Goodbye("suspension", 5));
    }

    /// <summary>Despedida rápida (apagado, suspensión, parada, actualización). No espera más de unos segundos.</summary>
    public void Goodbye(string reason, int seconds)
    {
        var s = AppSettings.Load();
        if (!s.SocEnabled) return;
        try
        {
            var t = SocClient.SendAsync(s, "adios", new { motivo = reason }, seconds);
            t.Wait(TimeSpan.FromSeconds(seconds + 1));
        }
        catch { }
    }

    private async Task TickAsync()
    {
        if (!await _busy.WaitAsync(0)) return; // la vuelta anterior aún no ha terminado (p. ej. subiendo un informe)
        try
        {
            var s = AppSettings.Load();
            if (!s.SocEnabled) return;
            bool sentSomething = await SendAlertsAsync(s);
            if (!sentSomething && DateTime.Now - _lastBeat >= BeatEvery && DateTime.Now >= _beatNotBefore)
                if (await TrySendAsync(s, "latido", _status(), 30)) _lastBeat = DateTime.Now;
            await SendReportsAsync(s);
        }
        catch (Exception ex) { _log("⚠ Error en el SOC familiar: " + ex.Message); }
        finally { _busy.Release(); }
    }

    private async Task<bool> SendAlertsAsync(AppSettings s)
    {
        // Solo se lee el registro si ha cambiado desde la última vez
        var since = _state.LastAlert;
        var days = since.Date < DateTime.Today ? new[] { DateTime.Today.AddDays(-1), DateTime.Today } : new[] { DateTime.Today };
        DateTime newest = days.Select(d => File.GetLastWriteTimeUtc(LogStore.FilePath(LogKind.Seguridad, d))).Max();
        if (newest == _lastAlertFileWrite) return false;

        var pending = days.Where(d => d >= since.Date)
            .SelectMany(d => LogStore.Read(LogKind.Seguridad, d))
            .Where(e => e.Time > since && UrgentOutcomes.Contains(e.Outcome))
            .OrderBy(e => e.Time).Take(40).ToList();
        if (pending.Count == 0) { _lastAlertFileWrite = newest; return false; }

        var list = pending.Select(e => new
        {
            hora = e.Time.ToString("yyyy-MM-dd HH:mm:ss"),
            tipo = e.Outcome,
            texto = e.Text.TrimStart('⚠', ' '),
            programa = e.App ?? "",
            ip = e.Remote ?? ""
        }).ToList();
        var status = _status();
        if (!await TrySendAsync(s, "aviso", new { avisos = list, estado = status }, 45)) return false;
        _state.LastAlert = pending[^1].Time;
        SaveState();
        _lastBeat = DateTime.Now; // el aviso ya cuenta como latido
        return true;
    }

    private async Task SendReportsAsync(AppSettings s)
    {
        var yesterday = DateTime.Today.AddDays(-1);
        if (_state.LastReportDay >= yesterday) return;
        var first = _state.LastReportDay == default
            ? yesterday
            : new[] { _state.LastReportDay.AddDays(1), DateTime.Today.AddDays(-MaxReportDaysBack) }.Max();
        for (var day = first; day <= yesterday; day = day.AddDays(1))
        {
            bool hasLogs = File.Exists(LogStore.FilePath(LogKind.Seguridad, day)) || File.Exists(LogStore.FilePath(LogKind.Trafico, day));
            if (hasLogs)
            {
                string md = await AnalysisReport.BuildAsync(day, day, RuleStore.Load(), Array.Empty<ProcessSummary>());
                var data = new { nombre = $"{day:yyyy-MM-dd} {s.SocComputer}.md", contenido = md, dia = day.ToString("yyyy-MM-dd") };
                if (!await TrySendAsync(s, "informe", data, 120)) return; // se reintenta en el siguiente minuto
                _log($"SOC familiar: informe del {day:dd/MM/yyyy} enviado.");
            }
            _state.LastReportDay = day;
            SaveState();
        }
    }

    private async Task<bool> TrySendAsync(AppSettings s, string type, object data, int timeout)
    {
        string? error = await SocClient.SendAsync(s, type, data, timeout);
        if (error == null)
        {
            if (_lastError != null) _log("SOC familiar: vuelve a haber conexión con el buzón.");
            _lastError = null;
            return true;
        }
        if (error != _lastError) _log("⚠ SOC familiar: " + error + " Se reintentará.");
        _lastError = error;
        return false;
    }

    private static State LoadState()
    {
        try
        {
            if (File.Exists(StateFile))
                return JsonSerializer.Deserialize<State>(File.ReadAllText(StateFile)) ?? NewState();
        }
        catch { }
        return NewState();
    }

    // La primera vez no se manda el historial antiguo de avisos, solo lo que pase desde ahora
    private static State NewState() => new() { LastAlert = DateTime.Now };

    private void SaveState()
    {
        try
        {
            string tmp = StateFile + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_state));
            File.Move(tmp, StateFile, true);
        }
        catch { }
    }
}
