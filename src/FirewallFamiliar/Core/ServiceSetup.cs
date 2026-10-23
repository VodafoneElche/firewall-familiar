using System;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Threading;

namespace FirewallFamiliar.Core;

/// <summary>
/// Registra el servicio de Windows "Firewall Familiar", que bloquea desde que arranca el PC,
/// sin que nadie tenga que abrir el programa ni ser administrador.
/// Lo usa el instalador (--instalar-servicio y --quitar-servicio).
/// </summary>
public static class ServiceSetup
{
    public const string ServiceName = "FirewallFamiliar";

    public static bool IsInstalled
    {
        get
        {
            try { return ServiceController.GetServices().Any(s => s.ServiceName.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)); }
            catch { return false; }
        }
    }

    public static bool IsRunning
    {
        get
        {
            try
            {
                using var sc = new ServiceController(ServiceName);
                return sc.Status == ServiceControllerStatus.Running;
            }
            catch { return false; }
        }
    }

    public static void Install(string exe)
    {
        string bin = $"\\\"{exe}\\\" --servicio";
        if (Sc($"create {ServiceName} binPath= \"{bin}\" start= auto DisplayName= \"Firewall Familiar\"") != 0)
            Sc($"config {ServiceName} binPath= \"{bin}\" start= auto DisplayName= \"Firewall Familiar\"");
        Sc($"description {ServiceName} \"Cortafuegos familiar: aplica las reglas de bloqueo y guarda los registros aunque no haya nadie con la ventana abierta.\"");
        // Si se cae, Windows lo vuelve a arrancar
        Sc($"failure {ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/30000");
        Start();
    }

    public static void Start()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status != ServiceControllerStatus.Running && sc.Status != ServiceControllerStatus.StartPending) sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        }
        catch { }
    }

    public static void Stop()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status != ServiceControllerStatus.Stopped && sc.Status != ServiceControllerStatus.StopPending) sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
        }
        catch { }
    }

    public static void Uninstall()
    {
        Stop();
        Sc($"delete {ServiceName}");
        Thread.Sleep(500);
    }

    private static int Sc(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("sc.exe", args)
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true })!;
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            return p.ExitCode;
        }
        catch { return -1; }
    }
}
