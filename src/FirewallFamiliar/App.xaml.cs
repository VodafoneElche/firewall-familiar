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
    private TrayClient? _trayClient;

    private static bool IsElevated()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
    private EventWaitHandle? _showEvent;

    /// <summary>true si Windows se está apagando o cerrando sesión (entonces se cierra sin preguntar).</summary>
    public static bool IsSessionEnding { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args;

        // Llamado por el instalador: tareas sueltas y terminar
        if (args.Contains("--registrar-arranque") || args.Contains("--quitar-arranque"))
        {
            // La tarea de arranque de las versiones 0.5 ya no hace falta: ahora arranca el servicio
            try { Core.Installer.SetAutostart(false, Environment.ProcessPath!); } catch { }
            Shutdown();
            return;
        }
        if (args.Contains("--instalar-servicio"))
        {
            try { Core.Installer.SetAutostart(false, Environment.ProcessPath!); } catch { }
            try { Core.ServiceSetup.Install(Environment.ProcessPath!); } catch { }
            Shutdown();
            return;
        }
        if (args.Contains("--quitar-servicio"))
        {
            try { Core.ServiceSetup.Uninstall(); } catch { }
            Shutdown();
            return;
        }

        // El servicio de Windows: sin ventana, hasta que Windows lo pare
        if (args.Contains("--servicio"))
        {
            var serviceThread = new Thread(() =>
            {
                try { System.ServiceProcess.ServiceBase.Run(new Service.FirewallService()); }
                catch { }
                Dispatcher.BeginInvoke(() => Shutdown());
            })
            { IsBackground = true, Name = "Servicio" };
            serviceThread.Start();
            return;
        }

        // El icono junto al reloj de cada usuario (sin permisos de administrador)
        if (args.Contains("--icono"))
        {
            _mutex = new Mutex(true, @"Local\FirewallFamiliar-icono", out bool firstIcon);
            if (!firstIcon) { _mutex = null; Shutdown(); return; }
            DispatcherUnhandledException += (_, ev) => ev.Handled = true; // el icono no debe caerse nunca
            _trayClient = new TrayClient();
            return;
        }

        // La ventana completa necesita ser administrador: si no lo es, se pide permiso a Windows
        if (!IsElevated())
        {
            try
            {
                Process.Start(new ProcessStartInfo(Environment.ProcessPath!, string.Join(" ", args.Select(a => $"\"{a}\"")))
                { UseShellExecute = true, Verb = "runas" });
            }
            catch { /* se canceló */ }
            Shutdown();
            return;
        }

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
