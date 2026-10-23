using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using FirewallFamiliar.Core;
using FirewallFamiliar.Views;

namespace FirewallFamiliar;

/// <summary>
/// El icono junto al reloj de cada usuario (FirewallFamiliar.exe --icono). No necesita ser
/// administrador: el bloqueo lo hace el servicio, y el icono solo enseña el estado, avisa,
/// pregunta en modo "Preguntar" y deja cambiar el modo (con contraseña).
/// </summary>
public sealed class TrayClient
{
    private readonly TrayIcon _tray = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly int _session = Process.GetCurrentProcess().SessionId;
    private PipeChannel? _channel;
    private PipeMessage _status = new() { T = "estado" };
    private bool _connected;
    private long _lastIn = -1, _lastOut = -1;

    private readonly Queue<PipeMessage> _questions = new();
    private (int Id, AskWindow Window)? _asking;
    private readonly HashSet<int> _cancelled = new();

    public TrayClient()
    {
        _tray.OpenRequested += OpenFullWindow;
        _tray.LogsRequested += OpenFullWindow;
        _tray.AlertClicked += OpenFullWindow;
        _tray.ExitRequested += Exit;
        _tray.ModeRequested += RequestMode;
        _tray.BlockAllRequested += () =>
        {
            if (_status.Mode == FirewallMode.BloquearTodo) RequestUnblock();
            else RequestMode(FirewallMode.BloquearTodo);
        };
        _tray.SetText("Firewall Familiar - conectando...");
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        _ = ConnectLoopAsync();
    }

    // =====================================================================
    // Conexión con el servicio
    // =====================================================================

    private async Task ConnectLoopAsync()
    {
        bool warned = false;
        while (true)
        {
            var ch = await PipeChannel.ConnectAsync(3000);
            if (ch == null)
            {
                SetDisconnected();
                if (!warned && ServiceSetup.IsInstalled && !ServiceSetup.IsRunning)
                {
                    warned = true;
                    _tray.Alert("Firewall Familiar no está protegiendo",
                        "El servicio de Firewall Familiar está parado. Reinicia el PC o abre el programa para activarlo.", true);
                }
                await Task.Delay(5000);
                continue;
            }
            warned = false;
            _channel = ch;
            _connected = true;
            await ch.SendAsync(new PipeMessage { T = "hola" });
            while (true)
            {
                var m = await ch.ReadAsync();
                if (m == null) break;
                Handle(m);
            }
            ch.Dispose();
            _channel = null;
            SetDisconnected();
            await Task.Delay(1000);
        }
    }

    private void SetDisconnected()
    {
        _connected = false;
        _tray.SetText("Firewall Familiar - servicio no disponible");
        // Las preguntas pendientes ya no tienen a quién contestar
        _questions.Clear();
        if (_asking is { } a) { _cancelled.Add(a.Id); a.Window.Close(); }
    }

    private void Handle(PipeMessage m)
    {
        switch (m.T)
        {
            case "estado":
                _status = m;
                _tray.SetMode(m.Mode);
                break;
            case "aviso":
                if (_status.TrayAlerts || m.Title.StartsWith("Contraseña")) _tray.Alert(m.Title, m.Text, m.Warning);
                break;
            case "pregunta":
                _questions.Enqueue(m);
                ShowNextQuestion();
                break;
            case "cerrar-pregunta":
                if (_asking is { } a && a.Id == m.Id) { _cancelled.Add(m.Id); a.Window.Close(); }
                else
                {
                    var keep = _questions.Where(q => q.Id != m.Id).ToList();
                    _questions.Clear();
                    foreach (var q in keep) _questions.Enqueue(q);
                }
                break;
        }
    }

    private void Send(PipeMessage m)
    {
        if (_channel == null)
        {
            _tray.Alert("Firewall Familiar", "El servicio no responde. Inténtalo dentro de un momento.", true);
            return;
        }
        _ = _channel.SendAsync(m);
    }

    // =====================================================================
    // Cada segundo: flechas del icono
    // =====================================================================

    private void Tick()
    {
        // Si en esta misma sesión está abierta la ventana completa, ella ya tiene su icono
        _tray.Visible = !(_connected && _status.Paused && _status.GuiSession == _session);

        long rx = 0, tx = 0;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var st = nic.GetIPStatistics();
                rx += st.BytesReceived;
                tx += st.BytesSent;
            }
        }
        catch { }
        bool incoming = _lastIn >= 0 && rx > _lastIn;
        bool outgoing = _lastOut >= 0 && tx > _lastOut;
        _lastIn = rx;
        _lastOut = tx;
        _tray.Set(incoming, outgoing, _status.Mode == FirewallMode.BloquearTodo);
    }

    // =====================================================================
    // Preguntas del modo "Preguntar"
    // =====================================================================

    private void ShowNextQuestion()
    {
        if (_asking != null || _questions.Count == 0) return;
        var m = _questions.Dequeue();
        var c = new BlockedConnection
        {
            AppPath = m.Path,
            RemoteAddress = IPAddress.TryParse(m.Remote, out var ip) ? ip : null,
            RemotePort = m.RemotePort,
            Protocol = m.Protocol,
            NeedsAnswer = true
        };
        string description = "";
        try { description = FileVersionInfo.GetVersionInfo(m.Path).FileDescription ?? ""; } catch { }
        var w = new AskWindow(c, ProcessMonitor.LoadIcon(m.Path), description, false);
        _asking = (m.Id, w);
        w.Closed += (_, _) =>
        {
            _asking = null;
            if (!_cancelled.Remove(m.Id))
            {
                var answer = w.Answer;
                string password = "";
                bool allow = answer?.Allow == true;
                if (allow && m.ProtectAsk)
                {
                    password = PasswordWindow.AskText($"Para dejar que {ProcessMonitor.FileName(m.Path)} se conecte hace falta la contraseña.") ?? "";
                    if (password.Length == 0) allow = false;
                }
                Send(new PipeMessage { T = "respuesta", Id = m.Id, Allow = allow, Remember = answer?.Remember == true, Password = password });
            }
            ShowNextQuestion();
        };
        w.Show();
    }

    // =====================================================================
    // Menú del icono
    // =====================================================================

    private void RequestMode(FirewallMode mode)
    {
        if (mode == _status.Mode) return;
        string password = "";
        if (mode != FirewallMode.BloquearTodo && _status.ProtectRules && _status.HasPassword)
        {
            password = PasswordWindow.AskText("Escribe la contraseña para cambiar el modo de seguridad.") ?? "";
            if (password.Length == 0) return;
        }
        Send(new PipeMessage { T = "modo", Mode = mode, Password = password });
    }

    private void RequestUnblock()
    {
        string password = "";
        if (_status.ProtectRules && _status.HasPassword)
        {
            password = PasswordWindow.AskText("Escribe la contraseña para volver a abrir la red.") ?? "";
            if (password.Length == 0) return;
        }
        Send(new PipeMessage { T = "desbloquear", Password = password });
    }

    /// <summary>La ventana completa necesita un administrador: Windows pedirá permiso (o la contraseña del administrador).</summary>
    private void OpenFullWindow()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
        }
        catch (Win32Exception) { /* se canceló el permiso */ }
        catch (Exception ex) { _tray.Alert("Firewall Familiar", "No se pudo abrir: " + ex.Message, true); }
    }

    private void Exit()
    {
        var settings = AppSettings.Load();
        if (settings.ProtectExit && settings.HasPassword &&
            !PasswordWindow.Ask(null, settings, "Para quitar el icono hace falta la contraseña. La protección sigue funcionando aunque lo quites."))
            return;
        _timer.Stop();
        _tray.Dispose();
        _channel?.Dispose();
        Application.Current.Shutdown();
    }
}
