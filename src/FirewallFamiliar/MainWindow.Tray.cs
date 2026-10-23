using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using FirewallFamiliar.Core;
using FirewallFamiliar.Views;

namespace FirewallFamiliar;

/// <summary>
/// Parte de la ventana principal para el icono junto al reloj, la contraseña,
/// la instalación y el arranque con Windows.
/// </summary>
public partial class MainWindow
{
    private AppSettings _settings = AppSettings.Load();
    private TrayIcon? _tray;
    private bool _reallyExit;
    private bool _toldAboutTray;
    private ConsoleEvent? _lastAlert;

    /// <summary>Arrancar escondido junto al reloj (al iniciar Windows).</summary>
    public bool StartHidden { get; init; }

    private void InitTray()
    {
        try
        {
            _tray = new TrayIcon();
            _tray.OpenRequested += ShowFromTray;
            _tray.ExitRequested += ExitApp;
            _tray.LogsRequested += () => { ShowFromTray(); OnShowLogs(this, new RoutedEventArgs()); };
            _tray.BlockAllRequested += () => OnToggleBlockAll(this, new RoutedEventArgs());
            _tray.ModeRequested += SetMode;
            _tray.AlertClicked += () => { ShowFromTray(); if (_lastAlert != null) ShowDetails(_lastAlert); };
            _tray.SetMode(_rules.Mode);
        }
        catch (Exception ex)
        {
            Log("⚠ No se pudo poner el icono junto al reloj: " + ex.Message);
        }
        Closing += OnClosingToTray;
        UpdateProtectionMenu();
    }

    /// <summary>Llamado cada segundo: enciende las flechas del icono.</summary>
    private void UpdateTray(double rateIn, double rateOut) =>
        _tray?.Set(rateIn > 0, rateOut > 0, _rules.Mode == FirewallMode.BloquearTodo);

    public void ShowFromTray()
    {
        ShowInTaskbar = true;
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
    }

    /// <summary>Avisos importantes también en un globo junto al reloj.</summary>
    private void TrayAlert(ConsoleEvent e)
    {
        if (_tray == null || !_settings.TrayAlerts || e.Outcome is not ("Escaneo" or "Sospechoso")) return;
        _lastAlert = e;
        _tray.Alert(e.Outcome == "Escaneo" ? "Posible ataque bloqueado" : "Programa sospechoso",
            e.Text.TrimStart('⚠', ' ') + "\nPulsa aquí para ver los detalles.", true);
    }

    // =====================================================================
    // Cerrar = esconder junto al reloj
    // =====================================================================

    private void OnClosingToTray(object? sender, CancelEventArgs e)
    {
        if (_reallyExit || App.IsSessionEnding || _tray == null) return;
        e.Cancel = true;
        Hide();
        if (!_toldAboutTray)
        {
            _toldAboutTray = true;
            _tray.Alert("Firewall Familiar sigue protegiendo",
                "Está aquí, junto al reloj. Para cerrarlo del todo: clic derecho en el icono → Salir.", false);
        }
    }

    private void OnHideToTray(object sender, RoutedEventArgs e) => Close();

    private void ExitApp()
    {
        if (_settings.ProtectExit && !PasswordWindow.Ask(IsVisible ? this : null, _settings,
                "Para cerrar Firewall Familiar hace falta la contraseña. Al cerrarlo se quitan todos los bloqueos."))
            return;
        _reallyExit = true;
        Close();
    }

    private void OnExit(object sender, RoutedEventArgs e) => ExitApp();

    // =====================================================================
    // Contraseña
    // =====================================================================

    /// <summary>Pide la contraseña si está activada la protección de reglas. true = adelante.</summary>
    private bool Authorize(string why) =>
        !_settings.ProtectRules || PasswordWindow.Ask(IsVisible ? this : null, _settings, why);

    private void OnSetPassword(object sender, RoutedEventArgs e)
    {
        if (_settings.HasPassword && !PasswordWindow.Ask(this, _settings, "Escribe la contraseña actual para cambiarla."))
            return;
        var pwd = PasswordWindow.AskNew(this);
        if (pwd == null) return;
        _settings.SetPassword(pwd);
        SaveSettings();
        Log(pwd.Length == 0 ? "Contraseña quitada: cualquiera puede cambiar las reglas." : "Contraseña puesta.");
        UpdateProtectionMenu();
    }

    private void OnToggleProtection(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { Tag: string tag } item) return;
        if (!PasswordWindow.Ask(this, _settings, "Escribe la contraseña para cambiar la protección."))
        {
            UpdateProtectionMenu();
            return;
        }
        switch (tag)
        {
            case "Exit": _settings.ProtectExit = item.IsChecked; break;
            case "Rules": _settings.ProtectRules = item.IsChecked; break;
            case "Ask": _settings.ProtectAsk = item.IsChecked; break;
            case "Alerts": _settings.TrayAlerts = item.IsChecked; break;
        }
        SaveSettings();
        UpdateProtectionMenu();
    }

    private void UpdateProtectionMenu()
    {
        MenuPassword.Header = _settings.HasPassword ? "Cambiar o quitar la contraseña..." : "Poner contraseña...";
        MenuProtectExit.IsChecked = _settings.ProtectExit;
        MenuProtectRules.IsChecked = _settings.ProtectRules;
        MenuProtectAsk.IsChecked = _settings.ProtectAsk;
        MenuTrayAlerts.IsChecked = _settings.TrayAlerts;
        foreach (var m in new[] { MenuProtectExit, MenuProtectRules, MenuProtectAsk }) m.IsEnabled = _settings.HasPassword;

        try { MenuAutostart.IsChecked = Installer.AutostartEnabled; } catch { }
    }

    private void SaveSettings()
    {
        try { _settings.Save(); }
        catch (Exception ex) { Log("⚠ No se pudieron guardar los ajustes: " + ex.Message); }
    }

    // =====================================================================
    // Instalar, desinstalar y arrancar con Windows
    // =====================================================================

    private void OnToggleAutostart(object sender, RoutedEventArgs e)
    {
        bool enable = MenuAutostart.IsChecked;
        if (!Authorize("Escribe la contraseña para cambiar el arranque con Windows.")) { UpdateProtectionMenu(); return; }
        try
        {
            Installer.SetAutostart(enable, Environment.ProcessPath ?? Installer.InstalledExe);
            Log(enable ? "Se abrirá solo al iniciar sesión (desde " + Environment.ProcessPath + ")." : "Ya no se abrirá solo al iniciar sesión.");
        }
        catch (Exception ex)
        {
            Log("⚠ " + ex.Message);
        }
        UpdateProtectionMenu();
    }
}
