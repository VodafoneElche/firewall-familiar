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

    private Timer? _connTimer, _scanTimer, _updateTimer, _applyTimer;
    private bool _updating;

    private sealed class Client
    {
        public required PipeChannel Channel { get; init; }
        public required NamedPipeServerStream Server { get; init; }
        public int Session { get; init; }
    }

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
        // Al arrancar (o tras una actualización) el icono de cada usuario conectado
        Task.Delay(3000).ContinueWith(_ => SafeRun(() => SessionLauncher.LaunchInAllSessions(_exe, msg => Log(msg))));
    }

    public void Stop()
    {
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
            foreach (var w in _firewall.Apply(_rules, permits, Array.Empty<string>())) Log("⚠ " + w);
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
        if (c.Inbound && c.RemoteAddress != null) CheckScan(c);
        else if (c.RemoteAddress != null) lock (_scan) _scan.NoteOutbound(c.RemoteAddress, DateTime.Now);

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
        _badPasswords++;
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
            if (IPAddress.TryParse(c.RemoteAddress, out var seenIp)) lock (_scan) _scan.NoteOutbound(seenIp, DateTime.Now);
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

    /// <summary>Anota en el registro de seguridad y, si es importante, avisa en el icono de cada usuario.</summary>
    private void Log(string text, string outcome = "", BlockedConnection? c = null, string? app = null, int pid = 0)
    {
        var entry = new LogEntry
        {
            Time = DateTime.Now, Text = text, Outcome = outcome,
            App = app ?? (c != null && c.AppPath.Length > 0 ? c.AppPath : null), Pid = pid,
            Remote = c?.RemoteAddress?.ToString(), RemotePort = c?.RemotePort ?? 0, LocalPort = c?.LocalPort ?? 0,
            Protocol = c?.Protocol ?? "", Inbound = c?.Inbound ?? false
        };
        LogStore.Write(LogKind.Seguridad, entry);

        if (outcome is "Escaneo" or "Sospechoso")
        {
            var m = new PipeMessage
            {
                T = "aviso", Warning = true, Text = text.TrimStart('⚠', ' '), Path = entry.App ?? "",
                Title = outcome == "Escaneo" ? "Posible ataque bloqueado" : "Programa sospechoso"
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
                    case "hola": SendStatus(client); break;
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
