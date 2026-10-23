using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using FirewallFamiliar.Core;
using FirewallFamiliar.Models;
using FirewallFamiliar.Views;

namespace FirewallFamiliar;

/// <summary>
/// Parte de la ventana principal que se ocupa del bloqueo: modos, reglas,
/// ventanas de "¿permitir?" y avisos de conexiones bloqueadas.
/// </summary>
public partial class MainWindow
{
    private static readonly string WindowsDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    private readonly WfpFirewall _firewall = new();
    private RuleSet _rules = RuleStore.Load();

    /// <summary>Programas de Windows vistos en ejecución (se permiten solos si está activada la opción).</summary>
    private readonly HashSet<string> _windowsPaths = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Permisos automáticos que ya están aplicados en el motor de filtrado.</summary>
    private HashSet<string> _appliedPermits = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Permitidos solo hasta cerrar el programa ("Recordar" sin marcar).</summary>
    private readonly HashSet<string> _sessionAllows = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Programas por los que ya se ha preguntado en esta sesión y se dijo que no (sin recordar).</summary>
    private readonly HashSet<string> _sessionDenied = new(StringComparer.OrdinalIgnoreCase);

    private readonly Queue<BlockedConnection> _askQueue = new();
    private readonly HashSet<string> _askQueued = new(StringComparer.OrdinalIgnoreCase);
    private AskWindow? _askOpen;

    private readonly Dictionary<string, DateTime> _lastBlockLog = new();
    private int _blockedInThisSecond, _blockedOutThisSecond;
    private int _blockedTotal;

    private FirewallMode _modeBeforeBlockAll = FirewallMode.SinPreguntas;
    private bool _firewallReady;
    private bool _updatingModeUi;
    private DispatcherTimer? _applyTimer;

    // =====================================================================
    // Arranque
    // =====================================================================

    private void InitFirewall()
    {
        try
        {
            _firewall.Open();
            _firewall.Blocked += c => Dispatcher.BeginInvoke(() => OnBlocked(c));
            _firewallReady = true;
            Log("Cortafuegos activo. Reglas guardadas en " + RuleStore.FilePath);
        }
        catch (Exception ex)
        {
            Log("⚠ No se pudo activar el cortafuegos: " + ex.Message + " Solo funcionará el monitor.");
            CmbMode.IsEnabled = false;
            BtnBlockAll.IsEnabled = false;
            MenuSecurity.IsEnabled = false;
        }
        ApplyRules();
    }

    /// <summary>Envía las reglas actuales al motor de filtrado de Windows y actualiza la interfaz.</summary>
    private void ApplyRules()
    {
        UpdateModeUi();
        foreach (var row in _apps)
            row.Rule = row.Path.Length > 0 ? _rules.ActionFor(row.Path) : RuleAction.Preguntar;

        if (!_firewallReady) return;
        try
        {
            var autoPermits = new List<string> { "System" };
            string? self = Environment.ProcessPath;
            if (self != null) autoPermits.Add(self);
            if (_rules.AllowWindowsComponents) autoPermits.AddRange(_windowsPaths);
            autoPermits.AddRange(_sessionAllows);

            var warnings = _firewall.Apply(_rules, autoPermits, Array.Empty<string>());
            _appliedPermits = new HashSet<string>(autoPermits, StringComparer.OrdinalIgnoreCase);
            foreach (var w in warnings) Log("⚠ " + w);
        }
        catch (Exception ex)
        {
            Log("⚠ Error al aplicar las reglas: " + ex.Message);
        }
    }

    /// <summary>Aplica las reglas dentro de un momento (agrupa varios cambios seguidos en uno).</summary>
    private void ApplyRulesSoon()
    {
        if (_applyTimer == null)
        {
            _applyTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
            _applyTimer.Tick += (_, _) => { _applyTimer.Stop(); ApplyRules(); };
        }
        _applyTimer.Stop();
        _applyTimer.Start();
    }

    private void SaveRules()
    {
        try { RuleStore.Save(_rules); }
        catch (Exception ex) { Log("⚠ No se pudieron guardar las reglas: " + ex.Message); }
    }

    /// <summary>Llamado al ver un proceso de Windows nuevo: se le da permiso antes de que lo necesite.</summary>
    private void NoteWindowsComponent(string path)
    {
        if (!_windowsPaths.Add(path)) return;
        if (_firewallReady && _rules.AllowWindowsComponents && _rules.Mode == FirewallMode.Preguntar)
            ApplyRulesSoon();
    }

    private static bool IsWindowsComponent(string path) =>
        path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(path, "System", StringComparison.OrdinalIgnoreCase);

    // =====================================================================
    // Modos
    // =====================================================================

    private void SetMode(FirewallMode mode)
    {
        if (_rules.Mode == mode) { UpdateModeUi(); return; }
        if (mode == FirewallMode.BloquearTodo) _modeBeforeBlockAll = _rules.Mode;
        _rules.Mode = mode;
        SaveRules();
        ApplyRules();
        Log(mode switch
        {
            FirewallMode.SinPreguntas => "Modo: SIN PREGUNTAS. Se aplican tus reglas y se permite el resto.",
            FirewallMode.Preguntar => "Modo: PREGUNTAR. Se avisará cuando un programa nuevo quiera salir a Internet.",
            _ => "Modo: BLOQUEAR TODO. La red está cortada."
        });
    }

    private void UpdateModeUi()
    {
        _updatingModeUi = true;
        try
        {
            var mode = _rules.Mode;
            CmbMode.SelectedIndex = (int)mode;
            MenuModeAllow.IsChecked = mode == FirewallMode.SinPreguntas;
            MenuModeAsk.IsChecked = mode == FirewallMode.Preguntar;
            MenuModeBlock.IsChecked = mode == FirewallMode.BloquearTodo;

            bool blockAll = mode == FirewallMode.BloquearTodo;
            BtnBlockAllText.Text = blockAll ? "Desbloquear" : "Bloquear todo";
            BtnBlockAllIcon.Text = blockAll ? "" : ""; // candado abierto / cerrado
            BtnBlockAll.Background = blockAll ? new SolidColorBrush(Color.FromRgb(255, 205, 205)) : Brushes.Transparent;

            if (!_firewallReady)
            {
                StatusMode.Text = "Solo monitor (cortafuegos no disponible)";
                StatusMode.Foreground = Brushes.DarkOrange;
                return;
            }
            StatusMode.Text = mode switch
            {
                FirewallMode.SinPreguntas => "Sin preguntas",
                FirewallMode.Preguntar => "Preguntar",
                _ => "TODO BLOQUEADO"
            };
            StatusMode.Foreground = blockAll ? Brushes.Red : mode == FirewallMode.Preguntar ? Brushes.DarkGreen : Brushes.Black;
        }
        finally { _updatingModeUi = false; }
    }

    private void OnModeComboChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingModeUi || CmbMode.SelectedItem is not ComboBoxItem { Tag: string tag }) return;
        SetMode(Enum.Parse<FirewallMode>(tag));
    }

    private void OnMenuMode(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem { Tag: string tag }) SetMode(Enum.Parse<FirewallMode>(tag));
    }

    private void OnToggleBlockAll(object sender, RoutedEventArgs e)
    {
        SetMode(_rules.Mode == FirewallMode.BloquearTodo
            ? (_modeBeforeBlockAll == FirewallMode.BloquearTodo ? FirewallMode.SinPreguntas : _modeBeforeBlockAll)
            : FirewallMode.BloquearTodo);
    }

    // =====================================================================
    // Reglas
    // =====================================================================

    private void OnSetRule(object sender, RoutedEventArgs e)
    {
        if (SelectedApp is not { } app || sender is not MenuItem { Tag: string tag }) return;
        if (app.Path.Length == 0)
        {
            MessageBox.Show(this, "Windows no deja ver la ruta de este proceso, así que no se le puede poner una regla.",
                "Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var action = Enum.Parse<RuleAction>(tag);
        if (action == RuleAction.Bloquear && IsWindowsComponent(app.Path) &&
            MessageBox.Show(this,
                $"\"{app.Name}\" es un componente de Windows. Bloquearlo puede dejar sin Internet al equipo o a otros programas.\n\n¿Bloquearlo de todas formas?",
                "Bloquear componente de Windows", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;

        _rules.SetApp(app.Path, action);
        _sessionAllows.Remove(app.Path);
        _sessionDenied.Remove(app.Path);
        SaveRules();
        ApplyRules();
        Log(action switch
        {
            RuleAction.Permitir => $"Regla: {app.Name} PERMITIDO.",
            RuleAction.Bloquear => $"Regla: {app.Name} BLOQUEADO.",
            _ => $"Regla de {app.Name} quitada: seguirá el modo general."
        });
    }

    private void OnShowRules(object sender, RoutedEventArgs e)
    {
        var win = new RulesWindow(_rules) { Owner = this };
        if (win.ShowDialog() != true || win.Result == null) return;
        win.Result.Mode = _rules.Mode;
        _rules = win.Result;
        SaveRules();
        ApplyRules();
        Log($"Reglas actualizadas: {_rules.Apps.Count} de programas, {_rules.Advanced.Count} avanzadas.");
    }

    private void OnOpenRulesFolder(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(RuleStore.Folder);
        Process.Start("explorer.exe", $"\"{RuleStore.Folder}\"");
    }

    // =====================================================================
    // Conexiones bloqueadas y preguntas
    // =====================================================================

    private void OnBlocked(BlockedConnection c)
    {
        if (c.Inbound) _blockedInThisSecond++; else _blockedOutThisSecond++;
        _blockedTotal++;

        string name = c.AppPath.Length == 0 ? "(programa desconocido)" : ProcessMonitor.FileName(c.AppPath);

        if (c.NeedsAnswer && c.AppPath.Length > 0)
        {
            // Componentes de Windows: se permiten solos si está activada la opción
            if (_rules.AllowWindowsComponents && IsWindowsComponent(c.AppPath))
            {
                _windowsPaths.Add(c.AppPath);
                if (!_appliedPermits.Contains(c.AppPath))
                {
                    _appliedPermits.Add(c.AppPath); // evita repetir el aviso mientras se aplica
                    Log($"Permitido automáticamente (componente de Windows): {name}");
                    ApplyRulesSoon();
                }
                return;
            }

            if (_sessionAllows.Contains(c.AppPath) || _sessionDenied.Contains(c.AppPath)) return;
            if (_rules.ActionFor(c.AppPath) != RuleAction.Preguntar) return; // ya tiene regla (se está aplicando)

            if (_askQueued.Add(c.AppPath))
            {
                Log($"{name} quiere conectarse a {c.Remote} ({c.Protocol}). Esperando tu respuesta...");
                _askQueue.Enqueue(c);
                ShowNextQuestion();
            }
            return;
        }

        // Bloqueado por una regla: se anota, sin repetir el mismo aviso más de una vez cada 30 s
        string key = c.AppPath + "|" + c.Reason;
        if (_lastBlockLog.TryGetValue(key, out var last) && DateTime.Now - last < TimeSpan.FromSeconds(30)) return;
        _lastBlockLog[key] = DateTime.Now;
        string dir = c.Inbound ? "desde" : "hacia";
        Log($"✖ Bloqueado: {name} {dir} {(c.Remote.Length > 0 ? c.Remote : "?")} {c.Protocol}  ({c.Reason})");
    }

    private void ShowNextQuestion()
    {
        if (_askOpen != null || _askQueue.Count == 0) return;
        var c = _askQueue.Dequeue();

        var row = _apps.FirstOrDefault(a => string.Equals(a.Path, c.AppPath, StringComparison.OrdinalIgnoreCase));
        var icon = row?.Icon ?? ProcessMonitor.LoadIcon(c.AppPath);
        string description = row?.Description ?? "";
        if (description.Length == 0)
        {
            try { description = FileVersionInfo.GetVersionInfo(c.AppPath).FileDescription ?? ""; } catch { }
        }
        bool hidden = row?.Kind == ProcessKind.Oculto;

        _askOpen = new AskWindow(c, icon, description, hidden);
        _askOpen.Closed += (_, _) =>
        {
            var answer = _askOpen?.Answer;
            _askOpen = null;
            _askQueued.Remove(c.AppPath);
            HandleAnswer(c, answer);
            ShowNextQuestion();
        };
        _askOpen.Show();
    }

    private void HandleAnswer(BlockedConnection c, AskAnswer? answer)
    {
        string name = ProcessMonitor.FileName(c.AppPath);
        if (answer == null)
        {
            _sessionDenied.Add(c.AppPath);
            Log($"Sin respuesta para {name}: sigue bloqueado hasta cerrar Firewall Familiar.");
            return;
        }

        if (answer.Remember)
        {
            _rules.SetApp(c.AppPath, answer.Allow ? RuleAction.Permitir : RuleAction.Bloquear);
            SaveRules();
        }
        else if (answer.Allow) _sessionAllows.Add(c.AppPath);
        else _sessionDenied.Add(c.AppPath);

        Log(answer.Allow
            ? $"✔ Permitido: {name}{(answer.Remember ? " (regla guardada)" : " (solo esta sesión)")}"
            : $"✖ Bloqueado: {name}{(answer.Remember ? " (regla guardada)" : " (solo esta sesión)")}");
        ApplyRules();
    }
}
