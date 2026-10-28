using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Service;

/// <summary>
/// Lo que hace el servicio de Windows, sin ventana: aplica las reglas, guarda los registros,
/// detecta escaneos y programas sospechosos, busca actualizaciones y habla con el icono de
/// cada usuario (preguntas, avisos y cambios de modo).
///
/// Cuando un administrador abre la ventana completa, el servicio le cede el control
/// ("pausa") y lo recupera al cerrarla.
/// </summary>
internal sealed class ServiceCore
{
    private static readonly string WindowsDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    private readonly object _gate = new();
    private readonly string _exe = Environment.ProcessPath ?? "";
    private readonly CancellationTokenSource _stop = new();

    private WfpFirewall? _firewall;
    private RuleSet _rules = new();
    private AppSettings _settings = new();
    private FirewallMode _modeBeforeBlockAll = FirewallMode.SinPreguntas;

    private readonly HashSet<string> _windowsPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _sessionAllows = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _deniedUntil = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _appliedPermits = new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<int, BlockedConnection> _questions = new();
    private readonly HashSet<string> _asking = new(StringComparer.OrdinalIgnoreCase);
    private int _nextQuestion;

    private readonly ScanDetector _scan = new();
    private readonly Dictionary<string, DateTime> _lastTrafficLog = new();
    private readonly Dictionary<string, DateTime> _lastBlockLog = new();
    private readonly HashSet<string> _alertedSuspicious = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _signaturePending = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _knownConnections = new();
    private readonly Dictionary<int, string> _pathByPid = new();

    private readonly List<Client> _clients = new();
    private Client? _gui;
    private int _badPasswords;
    private DateTime _badPasswordsSince;

    private Timer? _connTimer, _scanTimer, _updateTimer, _applyTimer, _remoteTimer;
    private bool _updating, _installingUpdate;
    private SocReporter? _soc;
    private Timer? _avTimer, _uploadTimer, _beaconTimer;
    private UploadMonitor? _uploads;
    private DnsWatcher? _dns;
    /// <summary>Último aviso de programa espía por indicador (para no repetir correos).</summary>
    private readonly Dictionary<string, DateTime> _spyAlerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _hashChecked = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _beaconAlerts = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>
    /// Hasta dónde se han revisado las detecciones del antivirus. Se guarda en disco para que una detección
    /// justo antes de apagar el PC se avise al encenderlo.
    /// </summary>
    private DateTime _avSince = LoadAvSince();
    private static readonly string AvSinceFile = Path.Combine(RuleStore.Folder, "antivirus-revisado.txt");

    private static DateTime LoadAvSince()
    {
        try
        {
            if (File.Exists(AvSinceFile) && DateTime.TryParse(File.ReadAllText(AvSinceFile).Trim(), System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var t))
                return t < DateTime.Now.AddDays(-2) ? DateTime.Now.AddDays(-2) : t;
        }
        catch { }
        return DateTime.Now;
    }

    private void SaveAvSince()
    {
        try { File.WriteAllText(AvSinceFile, _avSince.ToString("o")); } catch { }
    }
    /// <summary>Al volver de la suspensión llegan respuestas viejas (router, DNS...): no cuentan como escaneo.</summary>
    private DateTime _quietScanUntil = DateTime.Now.AddSeconds(90);
    private RemoteAccessMonitor? _remote;

    private sealed class Client
    {
        public required PipeChannel Channel { get; init; }
        public required NamedPipeServerStream Server { get; init; }
        public int Session { get; init; }
        /// <summary>Es el icono de un usuario (los iconos saludan con "hola"; la ventana completa no).</summary>
        public bool IsTray { get; set; }
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, TaskCompletionSource<string?>> _relayWaits = new();
    private int _relayId;

    /// <summary>
    /// Plan B del SOC: pide a un icono (que funciona con la cuenta del usuario) que mande el mensaje al buzón.
    /// Devuelve null si ha llegado bien.
    /// </summary>
    private async Task<string?> RelayToTrayAsync(string url, string json, int timeoutSeconds)
    {
        Client? tray;
        lock (_clients) tray = _clients.Where(c => c.IsTray && c != _gui).OrderBy(c => c.Session == ActiveConsoleSession() ? 0 : 1).FirstOrDefault();
        if (tray == null) return "No hay ningún icono conectado.";
        int id = Interlocked.Increment(ref _relayId);
        var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _relayWaits[id] = tcs;
        try
        {
            if (!await tray.Channel.SendAsync(new PipeMessage { T = "soc-enviar", Id = id, Path = url, Text = json, RemotePort = timeoutSeconds }))
                return "No se pudo hablar con el icono.";
            var done = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromSeconds(timeoutSeconds + 5)));
            return done == tcs.Task ? tcs.Task.Result : "El icono no contestó.";
        }
        finally { _relayWaits.TryRemove(id, out _); }
    }

    private static int ActiveConsoleSession() => (int)WTSGetActiveConsoleSessionId();

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    // =====================================================================
    // Arranque y parada
    // =====================================================================

    public void Start()
    {
        Log($"Servicio de Firewall Familiar iniciado (versión {Updater.Current.ToString(3)}).");
        LogStore.Error += msg => Log("⚠ " + msg);
        LoadPreviousAlerts();
        lock (_gate) OpenFirewall();

        _ = Task.Run(AcceptClientsAsync);
        _connTimer = new Timer(_ => SafeRun(PollConnections), null, 2000, 2000);
        _scanTimer = new Timer(_ => SafeRun(() => { lock (_gate) CheckPortScanOption(); }), null, 60000, 60000);
        _updateTimer = new Timer(_ => _ = CheckUpdatesAsync(), null, TimeSpan.FromMinutes(2), TimeSpan.FromHours(6));
        // SOC familiar y detector de control remoto (siguen funcionando aunque la ventana esté abierta)
        _soc = new SocReporter(msg => Log(msg), SocStatus, RelayToTrayAsync);
        _soc.Start();
        _remote = new RemoteAccessMonitor(
            (text, app, pid, remote, rport, lport) => Log(text, "AccesoRemoto", null, app, pid, remote, rport, lport),
            pid => pid == 4 ? "System" : pid <= 4 ? "" : FileDetails.ProperCase(NativeMethods.GetProcessPath(pid) ?? ""));
        _remoteTimer = new Timer(_ => SafeRun(() => _remote.Check()), null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(20));
        _avTimer = new Timer(_ => SafeRun(CheckAntivirus), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(2));
        // Subidas grandes y programas que "llaman a casa"
        _uploads = new UploadMonitor(
            pid => pid <= 4 ? "" : FileDetails.ProperCase(NativeMethods.GetProcessPath(pid) ?? ""),
            (text, outcome, app, ip) => Log(text, outcome, null, app, 0, ip));
        if (_uploads.Start() is { } upErr) Log("⚠ No se pudo vigilar las subidas de datos: " + upErr);
        _uploadTimer = new Timer(_ => SafeRun(() => _uploads.Check()), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        _beaconTimer = new Timer(_ => SafeRun(CheckBeacons), null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30));
        // Programas espía conocidos: nombres que se preguntan al DNS
        Log($"Listas de programas espía (Amnesty, Citizen Lab, ECHAP): {SpyIndicators.DomainCount} dominios, " +
            $"{SpyIndicators.IpCount} IPs bloqueadas y {SpyIndicators.HashCount} huellas de archivos.");
        _dns = new DnsWatcher((name, ips, pid) => SafeRun(() => OnDnsQuery(name, ips, pid)));
        if (_dns.Start() is { } dnsErr) Log("⚠ No se pudo vigilar las consultas DNS: " + dnsErr);
        // Al arrancar (o tras una actualización) el icono de cada usuario conectado
        Task.Delay(3000).ContinueWith(_ => SafeRun(() => SessionLauncher.LaunchInAllSessions(_exe, msg => Log(msg))));
    }

    /// <summary>Se para el servicio. <paramref name="shutdown"/>: porque se apaga o reinicia el PC.</summary>
    public void Stop(bool shutdown = false)
    {
        string reason = shutdown ? "apagado" : _installingUpdate || InstallerRunning("Instalar") ? "actualizacion"
            : InstallerRunning("unins") ? "desinstalacion" : "parada";
        Log(reason switch
        {
            "apagado" => "El PC se apaga o se reinicia.",
            "actualizacion" => "Se para el servicio para instalar una versión nueva.",
            "desinstalacion" => "⚠ Se está DESINSTALANDO Firewall Familiar.",
            _ => "⚠ Alguien ha parado el servicio de Firewall Familiar: el PC se queda sin protección."
        });
        _remoteTimer?.Dispose();
        _avTimer?.Dispose();
        _uploadTimer?.Dispose();
        _beaconTimer?.Dispose();
        _uploads?.Dispose();
        _dns?.Dispose();
        _soc?.Stop();
        _soc?.Goodbye(reason, shutdown ? 8 : 5);
        _stop.Cancel();
        _connTimer?.Dispose();
        _scanTimer?.Dispose();
        _updateTimer?.Dispose();
        _applyTimer?.Dispose();
        lock (_gate)
        {
            CloseFirewall();
        }
        lock (_clients)
        {
            foreach (var c in _clients) c.Channel.Dispose();
            _clients.Clear();
        }
        Log("Servicio de Firewall Familiar detenido.");
    }

    public void OnSuspend()
    {
        Log("El PC entra en suspensión.");
        _soc?.Goodbye("suspension", 4);
    }

    /// <summary>Si el antivirus (Trend Micro, Defender) ha detectado algo, se avisa como alerta.</summary>
    private void CheckAntivirus()
    {
        var checkedAt = DateTime.Now;
        var found = AntivirusInfo.DetectionsSince(_avSince);
        foreach (var (time, source, text) in found.Take(10))
            Log($"⚠ ANTIVIRUS ({source}) {(time.Date == DateTime.Today ? "" : $"el {time:dd/MM} ")}a las {time:HH:mm:ss}: {text}", "Alerta");
        if (found.Count > 0) _avSince = found[^1].Time;
        else if (checkedAt.AddMinutes(-1) > _avSince) _avSince = checkedAt.AddMinutes(-1); // margen por si Windows apunta el evento con retraso
        SaveAvSince();

        // Registros propios de Trend Micro: si crecen, hay una detección nueva
        var sizes = TrendLogs.UrgentSizes();
        if (_trendSizes != null)
            foreach (var (path, size) in sizes)
            {
                if (!_trendSizes.TryGetValue(path, out var before) || size == before) continue;
                var lines = TrendLogs.NewLines(path, size < before ? 0 : before);
                if (lines.Count == 0) continue;
                Log($"⚠ TREND MICRO: {TrendLogs.WhatIs(path)}: {TrendLogs.Summary(lines)}", "Alerta");
            }
        _trendSizes = sizes;
    }

    private Dictionary<string, long>? _trendSizes;

    /// <summary>
    /// Programas que se conectan al mismo sitio como un reloj (últimas 3 horas). Solo se avisa al momento
    /// si además el programa no tiene firma o vive en una carpeta rara; el resto sale en el informe diario.
    /// </summary>
    private void CheckBeacons()
    {
        var since = DateTime.Now.AddHours(-3);
        var traffic = LogStore.Read(LogKind.Trafico, DateTime.Today).Where(e => e.Time >= since).ToList();
        if (since.Date < DateTime.Today)
            traffic.AddRange(LogStore.Read(LogKind.Trafico, since.Date).Where(e => e.Time >= since));
        foreach (var b in Beacons.Find(traffic))
        {
            if (IsWindowsComponent(b.App)) continue;
            var sig = Signature.Get(b.App);
            bool suspicious = sig.Status == SignatureStatus.NoValida ||
                              (sig.Status == SignatureStatus.SinFirma && Suspicion.OddFolder(b.App) != null) ||
                              (sig.Status == SignatureStatus.SinFirma && !b.App.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase));
            if (!suspicious) continue;
            string key = b.App + "|" + b.Remote;
            if (_beaconAlerts.TryGetValue(key, out var last) && DateTime.Now - last < TimeSpan.FromDays(1)) continue;
            _beaconAlerts[key] = DateTime.Now;
            Log($"⚠ POSIBLE ESPÍA: {ProcessMonitor.FileName(b.App)} se conecta a {b.Remote} cada {Beacons.IntervalText(b.Interval)} " +
                $"como un reloj ({b.Count} veces desde las {b.First:HH:mm}) y no tiene firma digital. Así suelen \"llamar a casa\" los programas espía.",
                "Sospechoso", null, b.App, 0, b.Remote);
        }
    }

    /// <summary>Se ha encendido o apagado la pantalla, o se ha abierto o cerrado la tapa.</summary>
    public void OnScreenOrLid() => _soc?.OnScreenOrLid();

    /// <summary>
    /// Un usuario cierra sesión: casi siempre es porque se apaga el PC. Al apagar ya no suele haber red
    /// para despedirse, así que la despedida se manda ahora; si el PC sigue encendido, el latido de
    /// minuto y medio después lo vuelve a poner como activo.
    /// </summary>
    public void OnLogoff() => _soc?.OnScreenOrLid("apagado");

    public void OnResume()
    {
        _quietScanUntil = DateTime.Now.AddSeconds(90);
        Log("El PC vuelve de la suspensión.");
        _soc?.OnResume();
    }

    private static bool InstallerRunning(string part)
    {
        foreach (var p in System.Diagnostics.Process.GetProcesses())
            using (p)
            {
                try
                {
                    string n = p.ProcessName;
                    if (n.Contains(part, StringComparison.OrdinalIgnoreCase) &&
                        (part != "unins" || File.Exists(Path.Combine(AppContext.BaseDirectory, n + ".exe")))) return true;
                }
                catch { }
            }
        return false;
    }

    /// <summary>Lo que se cuenta al buzón del SOC en cada latido.</summary>
    private object SocStatus()
    {
        int trays;
        lock (_clients) trays = _clients.Count(x => x != _gui);
        lock (_gate)
            return new
            {
                modo = ModeText(_rules.Mode),
                protegiendo = _firewall != null || _gui != null,
                ventanaAbierta = _gui != null,
                usuariosConIcono = trays
            };
    }

    /// <summary>Un usuario acaba de iniciar sesión: se le pone el icono.</summary>
    public void OnLogon(int session) =>
        Task.Delay(4000).ContinueWith(_ => SafeRun(() => SessionLauncher.LaunchInSession(session, _exe, msg => Log(msg))));

    private void SafeRun(Action a)
    {
        try { a(); } catch (Exception ex) { Log("⚠ Error interno del servicio: " + ex.Message); }
    }

    private void OpenFirewall()
    {
        _rules = RuleStore.Load();
        foreach (var a in _rules.Apps) a.Path = FileDetails.ProperCase(a.Path);
        _settings = AppSettings.Load();
        try
        {
            var fw = new WfpFirewall(service: true);
            fw.Open();
            // Se atienden en otro hilo: el aviso llega desde Windows y no hay que hacerle esperar
            fw.Blocked += c => ThreadPool.QueueUserWorkItem(_ => SafeRun(() => OnBlocked(c)));
            fw.ForeignInboundBlocked += c => ThreadPool.QueueUserWorkItem(_ => SafeRun(() => OnInboundAttempt(c)));
            _firewall = fw;
            CheckPortScanOption();
            ApplyRules();
            Log("Bloqueo activo. Modo: " + ModeText(_rules.Mode) + ".");
        }
        catch (Exception ex)
        {
            _firewall?.Dispose();
            _firewall = null;
            Log("⚠ El servicio no pudo activar el cortafuegos: " + ex.Message);
        }
    }

    private void CloseFirewall()
    {
        _firewall?.Dispose(); // se quitan nuestros filtros
        _firewall = null;
        _questions.Clear();
        _asking.Clear();
    }

    private void CheckPortScanOption()
    {
        if (_firewall?.EnsurePortScanEvents() is { } msg) Log(msg);
    }

    // =====================================================================
    // Reglas
    // =====================================================================

    private void ApplyRules()
    {
        if (_firewall == null) return;
        try
        {
            var permits = new List<string> { "System" };
            if (_exe.Length > 0) permits.Add(_exe);
            if (_rules.AllowWindowsComponents) permits.AddRange(_windowsPaths);
            permits.AddRange(_sessionAllows);
            foreach (var w in _firewall.Apply(_rules, permits, Array.Empty<string>(), SpyIndicators.BlockList())) Log("⚠ " + w);
            _appliedPermits = new HashSet<string>(permits, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) { Log("⚠ Error al aplicar las reglas: " + ex.Message); }
    }

    private void ApplyRulesSoon()
    {
        _applyTimer ??= new Timer(_ => SafeRun(() => { lock (_gate) ApplyRules(); }));
        _applyTimer.Change(400, Timeout.Infinite);
    }

    private void SaveRules()
    {
        try { RuleStore.Save(_rules); }
        catch (Exception ex) { Log("⚠ No se pudieron guardar las reglas: " + ex.Message); }
    }

    private static bool IsWindowsComponent(string path) =>
        path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(path, "System", StringComparison.OrdinalIgnoreCase);

    private static string ModeText(FirewallMode m) => m switch
    {
        FirewallMode.SinPreguntas => "sin preguntas",
        FirewallMode.Preguntar => "preguntar",
        _ => "BLOQUEAR TODO"
    };

    // =====================================================================
    // Conexiones bloqueadas y preguntas
    // =====================================================================

    private void OnBlocked(BlockedConnection c)
    {
        LogTrafficBlock(c);
        if (c.Reason == WfpFirewall.SpyFilterName && c.RemoteAddress != null)
        {
            string family = SpyIndicators.MatchIp(c.RemoteAddress) ?? "programa espía";
            string who = c.AppPath.Length > 0 ? ProcessMonitor.FileName(c.AppPath) : "Un programa";
            if (SpyDue("ip|" + c.RemoteAddress))
                Log(c.Inbound
                    ? $"⚠ PROGRAMA ESPÍA: {c.RemoteAddress} intentó conectarse a este PC. Esa dirección aparece en las listas públicas de {family}. Bloqueado."
                    : $"⚠ PROGRAMA ESPÍA: {who} intentó conectarse a {c.RemoteAddress}, una dirección que aparece en las listas públicas de {family}. Bloqueado.",
                    "Alerta", c);
            return;
        }
        if (c.Inbound && c.RemoteAddress != null) CheckScan(c);
        else if (c.RemoteAddress != null) lock (_scan) _scan.NoteOutbound(c.RemoteAddress, DateTime.Now, c.RemotePort);

        lock (_gate)
        {
            if (_firewall == null) return;
            string name = c.AppPath.Length == 0 ? "(programa desconocido)" : ProcessMonitor.FileName(c.AppPath);

            if (c.NeedsAnswer && c.AppPath.Length > 0)
            {
                if (_rules.AllowWindowsComponents && IsWindowsComponent(c.AppPath))
                {
                    _windowsPaths.Add(c.AppPath);
                    if (_appliedPermits.Add(c.AppPath))
                    {
                        Log($"Permitido automáticamente (componente de Windows): {name}", "Permitido", c);
                        ApplyRulesSoon();
                    }
                    return;
                }
                if (_sessionAllows.Contains(c.AppPath)) return;
                if (_deniedUntil.TryGetValue(c.AppPath, out var until) && DateTime.Now < until) return;
                if (_rules.ActionFor(c.AppPath) != RuleAction.Preguntar) return;
                if (_asking.Contains(c.AppPath)) return;

                List<Client> trays;
                lock (_clients) trays = _clients.Where(x => x != _gui).ToList();
                if (trays.Count == 0)
                {
                    _deniedUntil[c.AppPath] = DateTime.Now.AddMinutes(5);
                    Log($"✖ Bloqueado: {name} quiere conectarse a {c.Remote}, pero no hay nadie con sesión iniciada para preguntarle.", "Bloqueado", c);
                    return;
                }
                int id = ++_nextQuestion;
                _questions[id] = c;
                _asking.Add(c.AppPath);
                Log($"{name} quiere conectarse a {c.Remote} ({c.Protocol}). Esperando respuesta...", "Pregunta", c);
                var q = new PipeMessage
                {
                    T = "pregunta", Id = id, Path = c.AppPath, Remote = c.RemoteAddress?.ToString() ?? "",
                    RemotePort = c.RemotePort, Protocol = c.Protocol, ProtectAsk = _settings.ProtectAsk && _settings.HasPassword
                };
                foreach (var t in trays) _ = t.Channel.SendAsync(q);
                return;
            }

            string key = c.AppPath + "|" + c.Reason;
            if (_lastBlockLog.TryGetValue(key, out var last) && DateTime.Now - last < TimeSpan.FromSeconds(30)) return;
            _lastBlockLog[key] = DateTime.Now;
            string dir = c.Inbound ? "desde" : "hacia";
            Log($"✖ Bloqueado: {name} {dir} {(c.Remote.Length > 0 ? c.Remote : "?")} {c.Protocol}  ({c.Reason})", "Bloqueado", c);
        }
    }

    private void OnAnswer(Client from, PipeMessage m)
    {
        lock (_gate)
        {
            if (!_questions.Remove(m.Id, out var c)) return; // ya contestada en otra sesión
            _asking.Remove(c.AppPath);
            List<Client> others;
            lock (_clients) others = _clients.Where(x => x != from).ToList();
            foreach (var other in others)
                _ = other.Channel.SendAsync(new PipeMessage { T = "cerrar-pregunta", Id = m.Id });

            string name = ProcessMonitor.FileName(c.AppPath);
            if (m.Allow && _settings.ProtectAsk && _settings.HasPassword && !CheckPassword(m.Password))
            {
                _deniedUntil[c.AppPath] = DateTime.Now.AddMinutes(5);
                Log($"✖ Bloqueado: {name} (contraseña incorrecta para permitirlo)", "Bloqueado", c);
                _ = from.Channel.SendAsync(new PipeMessage { T = "aviso", Title = "Contraseña incorrecta", Text = $"{name} sigue bloqueado.", Warning = true });
                return;
            }
            if (m.Remember)
            {
                _rules.SetApp(c.AppPath, m.Allow ? RuleAction.Permitir : RuleAction.Bloquear);
                SaveRules();
            }
            else if (m.Allow) _sessionAllows.Add(c.AppPath);
            else _deniedUntil[c.AppPath] = DateTime.MaxValue;

            Log(m.Allow
                ? $"✔ Permitido: {name}{(m.Remember ? " (regla guardada)" : " (hasta reiniciar)")}"
                : $"✖ Bloqueado: {name}{(m.Remember ? " (regla guardada)" : " (hasta reiniciar)")}",
                m.Allow ? "Permitido" : "Bloqueado", c);
            ApplyRules();
        }
    }

    private void OnModeRequest(Client from, PipeMessage m)
    {
        lock (_gate)
        {
            var target = m.T == "desbloquear"
                ? (_modeBeforeBlockAll == FirewallMode.BloquearTodo ? FirewallMode.SinPreguntas : _modeBeforeBlockAll)
                : m.Mode;
            if (target == _rules.Mode) { SendStatus(from); return; }
            bool needsPassword = target != FirewallMode.BloquearTodo && _settings.ProtectRules && _settings.HasPassword;
            if (needsPassword && !CheckPassword(m.Password))
            {
                _ = from.Channel.SendAsync(new PipeMessage { T = "aviso", Title = "Contraseña incorrecta", Text = "No se ha cambiado el modo.", Warning = true });
                return;
            }
            if (target == FirewallMode.BloquearTodo) _modeBeforeBlockAll = _rules.Mode;
            _rules.Mode = target;
            SaveRules();
            ApplyRules();
            Log("Modo: " + ModeText(target).ToUpperInvariant() + " (cambiado desde el icono junto al reloj).");
            BroadcastStatus();
        }
    }

    private bool CheckPassword(string password)
    {
        if (DateTime.Now - _badPasswordsSince > TimeSpan.FromMinutes(1)) { _badPasswords = 0; _badPasswordsSince = DateTime.Now; }
        if (_badPasswords >= 5) return false; // demasiados intentos: esperar un minuto
        _settings = AppSettings.Load();
        if (_settings.CheckPassword(password)) return true;
        if (++_badPasswords == 5)
            Log("⚠ ALGUIEN ESTÁ PROBANDO CONTRASEÑAS: 5 contraseñas incorrectas en un minuto en el icono de Firewall Familiar.", "Alerta");
        return false;
    }

    // =====================================================================
    // Intentos de entrada, escaneos y programas sospechosos
    // =====================================================================

    private void OnInboundAttempt(BlockedConnection c)
    {
        lock (_gate) if (_firewall == null) return;
        LogTrafficBlock(c);
        CheckScan(c);
    }

    private void CheckScan(BlockedConnection c)
    {
        if (c.RemoteAddress == null || c.LocalPort == 0) return;
        if (DateTime.Now < _quietScanUntil && c.LocalPort >= 1024) return;
        int ports;
        IReadOnlyList<int> list;
        lock (_scan)
        {
            ports = _scan.Add(c.RemoteAddress, c.RemotePort, c.LocalPort, DateTime.Now);
            if (ports == 0) return;
            list = _scan.PortsFrom(c.RemoteAddress);
        }
        string sample = string.Join(", ", list.Take(12)) + (list.Count > 12 ? "..." : "");
        string where = IpInfo.Special(c.RemoteAddress) != null ? " (de tu red de casa)" : "";
        Log($"⚠ POSIBLE ATAQUE: {c.RemoteAddress}{where} ha probado {ports} puertos distintos en menos de un minuto ({sample}). Bloqueado.",
            "Escaneo", c);
    }

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

    /// <summary>Programa que se conecta a Internet con firma no válida, o sin firma desde una carpeta rara.</summary>
    private void CheckSuspicious(string path, int pid)
    {
        if (path.Length == 0 || path == "System" || _alertedSuspicious.Contains(path)) return;
        var sig = Signature.Get(path);
        if (sig.Status == SignatureStatus.Pendiente) { _signaturePending.Add(path); return; }
        _signaturePending.Remove(path);

        var reasons = new List<string>();
        if (sig.Status == SignatureStatus.NoValida) reasons.Add("su firma digital NO es válida (" + sig.Detail + ")");
        if (sig.Status == SignatureStatus.SinFirma && Suspicion.OddFolder(path) is { } folder)
            reasons.Add("no tiene firma digital y funciona desde " + folder);
        if (reasons.Count == 0 || !_alertedSuspicious.Add(path)) return;
        lock (_gate) if (_rules.ActionFor(path) == RuleAction.Bloquear) return;

        Log($"⚠ PROGRAMA SOSPECHOSO: {ProcessMonitor.FileName(path)} (PID {pid}): {string.Join("; ", reasons)}. Se está conectando a Internet.",
            "Sospechoso", null, path, pid);
    }

    // =====================================================================
    // Registro de conexiones (lo mismo que hace la ventana, cada 2 segundos)
    // =====================================================================

    private int _polling;

    private void PollConnections()
    {
        if (Interlocked.Exchange(ref _polling, 1) == 1) return;
        try { PollConnectionsCore(); }
        finally { _polling = 0; }
    }

    private void PollConnectionsCore()
    {
        lock (_gate) if (_firewall == null && _gui != null) return; // la ventana se encarga
        var conns = ConnectionMonitor.GetAll();
        var listening = conns.Where(c => c.IsListening).Select(c => (c.Pid, c.LocalPort)).ToHashSet();
        var now = new HashSet<string>();
        var alive = new HashSet<int>();
        foreach (var c in conns)
        {
            alive.Add(c.Pid);
            if (c.IsListening || c.RemoteAddress.Length == 0) continue;
            if (IPAddress.TryParse(c.RemoteAddress, out var seenIp)) lock (_scan) _scan.NoteOutbound(seenIp, DateTime.Now, c.RemotePort);
            string key = $"{c.Pid}|{c.Protocol}|{c.Local}|{c.Remote}";
            now.Add(key);
            if (_knownConnections.Contains(key)) continue;
            if (!IPAddress.TryParse(c.RemoteAddress, out var ip) || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) continue;

            string path = PathOf(c.Pid);
            bool inbound = c.Protocol.StartsWith("TCP") && listening.Contains((c.Pid, c.LocalPort));
            string name = path.Length > 0 ? ProcessMonitor.FileName(path) : c.Pid == 4 ? "System" : c.Pid == 0 ? "Sistema" : $"PID {c.Pid}";
            LogStore.Write(LogKind.Trafico, new LogEntry
            {
                Time = DateTime.Now,
                Text = inbound ? $"{name}: conexión entrante desde {c.Remote}" : $"{name}: conexión con {c.Remote}",
                App = path.Length > 0 ? path : null,
                Pid = c.Pid, Remote = ip.ToString(), RemotePort = c.RemotePort, LocalPort = c.LocalPort,
                Protocol = c.Protocol.Replace("v6", ""), Inbound = inbound, Outcome = "Permitido"
            });
            if (path.Length > 0 && !IsWindowsComponent(path)) CheckSuspicious(path, c.Pid);
            if (SpyIndicators.MatchIp(ip) is { } spyFamily && SpyDue("ip|" + ip))
            {
                Log($"⚠ PROGRAMA ESPÍA: {name} está conectado a {ip}, una dirección que aparece en las listas públicas de {spyFamily}. " +
                    "Se bloquea desde ahora.", "Alerta", null, path.Length > 0 ? path : null, c.Pid, ip.ToString(), c.RemotePort, c.LocalPort);
                ApplyRulesSoon();
            }
            if (path.Length > 0 && !IsWindowsComponent(path)) CheckFileHash(path, c.Pid);
        }
        _knownConnections = now;
        foreach (var p in _signaturePending.ToList()) CheckSuspicious(p, 0);
        foreach (var dead in _pathByPid.Keys.Where(k => !alive.Contains(k)).ToList()) _pathByPid.Remove(dead);
    }

    private string PathOf(int pid)
    {
        if (pid <= 4) return pid == 4 ? "System" : "";
        if (_pathByPid.TryGetValue(pid, out var p)) return p;
        p = NativeMethods.GetProcessPath(pid) ?? "";
        if (p.Length > 0) p = FileDetails.ProperCase(p);
        _pathByPid[pid] = p;
        return p;
    }

    private void LogTrafficBlock(BlockedConnection c)
    {
        lock (_lastTrafficLog)
        {
            string key = $"{c.AppPath}|{c.RemoteAddress}|{c.RemotePort}|{c.LocalPort}|{c.Inbound}";
            if (_lastTrafficLog.TryGetValue(key, out var last) && c.Time - last < TimeSpan.FromSeconds(10)) return;
            _lastTrafficLog[key] = c.Time;
            if (_lastTrafficLog.Count > 5000)
                foreach (var k in _lastTrafficLog.Where(kv => c.Time - kv.Value > TimeSpan.FromSeconds(10)).Select(kv => kv.Key).ToList())
                    _lastTrafficLog.Remove(k);
        }
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

    // =====================================================================
    // Programas espía conocidos (listas públicas)
    // =====================================================================

    private bool SpyDue(string key)
    {
        lock (_spyAlerts)
        {
            if (_spyAlerts.TryGetValue(key, out var last) && DateTime.Now - last < TimeSpan.FromHours(6)) return false;
            _spyAlerts[key] = DateTime.Now;
            return true;
        }
    }

    /// <summary>El PC ha preguntado por un nombre: si es de un servidor espía, aviso y bloqueo de sus IPs.</summary>
    private void OnDnsQuery(string name, List<IPAddress> ips, int pid)
    {
        if (SpyIndicators.MatchDomain(name) is not { } hit) return;
        bool added = false;
        foreach (var ip in ips) added |= SpyIndicators.Learn(ip, hit.Family);
        if (added) lock (_gate) ApplyRules();
        if (!SpyDue("dns|" + hit.Domain)) return;
        string path = pid > 4 ? FileDetails.ProperCase(NativeMethods.GetProcessPath(pid) ?? "") : "";
        // Las consultas suele hacerlas el servicio DNS de Windows en nombre del programa
        bool dnsService = path.EndsWith(@"\svchost.exe", StringComparison.OrdinalIgnoreCase);
        string who = path.Length > 0 && !dnsService ? ProcessMonitor.FileName(path) : "Un programa de este PC";
        Log($"⚠ PROGRAMA ESPÍA: {who} ha buscado \"{name}\", un servidor que aparece en las listas públicas de {hit.Family}. " +
            (ips.Count > 0 ? $"Sus direcciones ({string.Join(", ", ips.Take(4))}) quedan bloqueadas. " : "") +
            "Puede ser una web o un enlace engañoso, o un programa espía instalado: revisa el PC.",
            "Alerta", null, path.Length > 0 && !dnsService ? path : null, pid, ips.Count > 0 ? ips[0].ToString() : null);
    }

    /// <summary>Una vez por programa: su huella SHA-256 contra la lista de programas espía (en segundo plano).</summary>
    private void CheckFileHash(string path, int pid)
    {
        lock (_hashChecked)
        {
            if (!_hashChecked.Add(path) || SpyIndicators.HashCount == 0) return;
        }
        Task.Run(() => SafeRun(() =>
        {
            if (SpyIndicators.MatchFile(path) is { } family)
                Log($"⚠ PROGRAMA ESPÍA: {ProcessMonitor.FileName(path)} (PID {pid}) es un archivo conocido de {family} " +
                    "según las listas públicas. Desconecta Internet y revisa el PC.", "Alerta", null, path, pid);
        }));
    }

    /// <summary>Anota en el registro de seguridad y, si es importante, avisa en el icono de cada usuario.</summary>
    private void Log(string text, string outcome = "", BlockedConnection? c = null, string? app = null, int pid = 0,
        string? remote = null, int remotePort = 0, int localPort = 0)
    {
        var entry = new LogEntry
        {
            Time = DateTime.Now, Text = text, Outcome = outcome,
            App = app ?? (c != null && c.AppPath.Length > 0 ? c.AppPath : null), Pid = pid,
            Remote = remote ?? c?.RemoteAddress?.ToString(), RemotePort = c?.RemotePort ?? remotePort, LocalPort = c?.LocalPort ?? localPort,
            Protocol = c?.Protocol ?? (remote != null ? "TCP" : ""), Inbound = c?.Inbound ?? false
        };
        LogStore.Write(LogKind.Seguridad, entry);

        if (SocReporter.UrgentOutcomes.Contains(outcome))
        {
            var m = new PipeMessage
            {
                T = "aviso", Warning = true, Text = text.TrimStart('⚠', ' '), Path = entry.App ?? "",
                Title = outcome switch
                {
                    "Escaneo" => "Posible ataque bloqueado",
                    "Sospechoso" => "Programa sospechoso",
                    "AccesoRemoto" => "Control remoto detectado",
                    _ => "Aviso de seguridad"
                }
            };
            List<Client> to;
            lock (_clients) to = _clients.ToList();
            foreach (var t in to) _ = t.Channel.SendAsync(m);
        }
    }

    // =====================================================================
    // Actualizaciones
    // =====================================================================

    private async Task CheckUpdatesAsync()
    {
        if (_updating) return;
        _updating = true;
        try
        {
            if (!AppSettings.Load().AutoUpdate || !Updater.InstalledWithSetup) return;
            var info = await Updater.CheckAsync();
            if (info == null) return;
            string v = info.Version.ToString(3);
            Log($"Descargando la versión {v}...");
            string file = await Updater.DownloadAsync(info);
            Log($"Instalando la versión {v}. La protección se reinicia en unos segundos.");
            _installingUpdate = true;
            Updater.RunInstaller(file); // el instalador para este servicio y lo vuelve a arrancar
        }
        catch (Exception ex) { Log("No se pudo buscar o instalar una versión nueva: " + ex.Message); }
        finally { _updating = false; }
    }

    // =====================================================================
    // Comunicación con el icono y con la ventana
    // =====================================================================

    private static PipeSecurity CreatePipeSecurity()
    {
        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return ps;
    }

    private async Task AcceptClientsAsync()
    {
        var security = CreatePipeSecurity();
        while (!_stop.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = NamedPipeServerStreamAcl.Create(PipeChannel.Name, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    4096, 4096, security);
                await server.WaitForConnectionAsync(_stop.Token);
                var s = server;
                server = null;
                _ = Task.Run(() => HandleClientAsync(s));
            }
            catch (OperationCanceledException) { server?.Dispose(); return; }
            catch (Exception ex)
            {
                server?.Dispose();
                Log("⚠ Error en la comunicación con el icono: " + ex.Message);
                await Task.Delay(2000);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream server)
    {
        GetNamedPipeClientSessionId(server.SafePipeHandle.DangerousGetHandle(), out uint session);
        var client = new Client { Channel = new PipeChannel(server), Server = server, Session = (int)session };
        lock (_clients) _clients.Add(client);
        try
        {
            SendStatus(client);
            while (!_stop.IsCancellationRequested)
            {
                var m = await client.Channel.ReadAsync(_stop.Token);
                if (m == null) break;
                switch (m.T)
                {
                    case "respuesta": OnAnswer(client, m); break;
                    case "modo":
                    case "desbloquear": OnModeRequest(client, m); break;
                    case "pausa": await OnPauseAsync(client); break;
                    case "hola": client.IsTray = true; SendStatus(client); break;
                    case "soc-resultado":
                        if (_relayWaits.TryGetValue(m.Id, out var wait)) wait.TrySetResult(m.Ok ? null : (m.Error.Length > 0 ? m.Error : "Error en el icono."));
                        break;
                    case "abrir-ventana": OnOpenWindow(client); break;
                }
            }
        }
        catch { }
        finally
        {
            lock (_clients) _clients.Remove(client);
            bool wasGui;
            bool anyTray;
            lock (_clients) anyTray = _clients.Any(x => x != _gui);
            lock (_gate)
            {
                wasGui = _gui == client;
                if (wasGui) _gui = null;
                if (!anyTray)
                {
                    // Nadie puede contestar las preguntas pendientes: siguen bloqueados un rato
                    foreach (var q in _questions.Values) _deniedUntil[q.AppPath] = DateTime.Now.AddMinutes(5);
                    _questions.Clear();
                    _asking.Clear();
                }
            }
            client.Channel.Dispose();
            if (wasGui)
            {
                Resume();
                // Mientras la ventana estaba abierta no hacía falta el icono: se vuelve a poner
                int guiSession = client.Session;
                _ = Task.Delay(2500).ContinueWith(_ => SafeRun(() => SessionLauncher.LaunchInSession(guiSession, _exe, msg => Log(msg))));
            }
        }
    }

    /// <summary>
    /// Un usuario pide abrir la ventana completa. Si es administrador se abre ya elevada, sin el aviso
    /// de Windows; si es una cuenta estándar se le contesta que no y Windows pedirá la contraseña.
    /// </summary>
    private void OnOpenWindow(Client client)
    {
        string? error = SessionLauncher.LaunchElevated(client.Session, _exe);
        if (error != null) Log("Ventana completa: se pide permiso a Windows (" + error + ").");
        _ = client.Channel.SendAsync(new PipeMessage { T = "ventana", Ok = error == null, Error = error ?? "" });
    }

    /// <summary>La ventana completa (de un administrador) toma el control hasta que se cierre.</summary>
    private async Task OnPauseAsync(Client client)
    {
        bool admin = false;
        string why = "";
        try
        {
            client.Server.RunAsClient(() =>
            {
                using var id = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
                admin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            });
        }
        catch (Exception ex) { why = ex.Message; }
        // Otra forma de comprobarlo: si el programa que se conecta tiene permisos elevados
        if (!admin && GetNamedPipeClientProcessId(client.Server.SafePipeHandle.DangerousGetHandle(), out uint pid))
            admin = IsElevated((int)pid);
        if (!admin) Log("La ventana pidió el control sin permisos de administrador" + (why.Length > 0 ? " (" + why + ")" : "") + ".");
        if (!admin)
        {
            await client.Channel.SendAsync(new PipeMessage { T = "pausado", Ok = false, Error = "Hace falta abrirlo como administrador." });
            return;
        }
        lock (_gate)
        {
            _gui = client;
            CloseFirewall();
        }
        Log("Ventana de Firewall Familiar abierta: ella aplica las reglas mientras esté abierta.");
        await client.Channel.SendAsync(new PipeMessage { T = "pausado", Ok = true });
        BroadcastStatus();
    }

    private void Resume()
    {
        Thread.Sleep(300); // que la ventana termine de quitar sus filtros
        lock (_gate)
        {
            if (_gui != null || _firewall != null) return;
            _sessionAllows.Clear();
            _deniedUntil.Clear();
            OpenFirewall();
        }
        BroadcastStatus();
    }

    private PipeMessage Status()
    {
        lock (_gate)
            return new PipeMessage
            {
                T = "estado", Mode = _rules.Mode, Paused = _gui != null, GuiSession = _gui?.Session ?? 0,
                HasPassword = _settings.HasPassword, ProtectAsk = _settings.ProtectAsk, ProtectRules = _settings.ProtectRules,
                ProtectExit = _settings.ProtectExit, TrayAlerts = _settings.TrayAlerts
            };
    }

    private void SendStatus(Client c) => _ = c.Channel.SendAsync(Status());

    private void BroadcastStatus()
    {
        var m = Status();
        List<Client> to;
        lock (_clients) to = _clients.ToList();
        foreach (var c in to) _ = c.Channel.SendAsync(m);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientSessionId(IntPtr pipe, out uint sessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint processId);

    private static bool IsElevated(int pid)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            if (!OpenProcessToken(p.Handle, 0x0008 /* TOKEN_QUERY */, out IntPtr token)) return false;
            try
            {
                return GetTokenInformation(token, 20 /* TokenElevation */, out int elevated, 4, out _) && elevated != 0;
            }
            finally { CloseHandle(token); }
        }
        catch { return false; }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int info, int length, out int returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
