using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

namespace FirewallFamiliar;

public partial class App : Application
{
    private const string MutexName = @"Global\FirewallFamiliar-instancia";
    private const string ShowEventName = @"Global\FirewallFamiliar-mostrar";

    private Mutex? _mutex;
    private EventWaitHandle? _showEvent;

    /// <summary>true si Windows se está apagando o cerrando sesión (entonces se cierra sin preguntar).</summary>
    public static bool IsSessionEnding { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args;

        // Tras instalar o actualizar: esperar a que se cierre la copia anterior
        var wait = args.FirstOrDefault(a => a.StartsWith("--esperar="));
        if (wait != null && int.TryParse(wait["--esperar=".Length..], out int oldPid))
        {
            try { using var old = Process.GetProcessById(oldPid); old.WaitForExit(20000); } catch { }
        }

        // Solo una copia a la vez: si ya hay una abierta, se le pide que se muestre
        _mutex = new Mutex(true, MutexName, out bool first);
        if (!first)
        {
            try { EventWaitHandle.OpenExisting(ShowEventName).Set(); } catch { }
            Shutdown();
            return;
        }

        var window = new MainWindow { StartHidden = args.Contains("--bandeja") };
        if (window.StartHidden)
        {
            // Se crea minimizado y sin botón en la barra, y al cargar se esconde junto al reloj
            window.ShowInTaskbar = false;
            window.WindowState = WindowState.Minimized;
        }
        MainWindow = window;
        window.Show();

        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        var t = new Thread(() =>
        {
            while (_showEvent.WaitOne())
                Dispatcher.BeginInvoke(() => window.ShowFromTray());
        })
        { IsBackground = true };
        t.Start();
    }

    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        IsSessionEnding = true;
        base.OnSessionEnding(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _mutex?.ReleaseMutex(); } catch { }
        base.OnExit(e);
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Mostrar el error en lugar de cerrar la aplicación sin avisar.
        MessageBox.Show("Se ha producido un error inesperado:\n\n" + e.Exception.Message,
            "Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
