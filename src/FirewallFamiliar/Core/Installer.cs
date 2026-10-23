using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace FirewallFamiliar.Core;

/// <summary>
/// Arranque con Windows: una tarea programada que abre el programa junto al reloj al iniciar
/// sesión, con permisos de administrador y sin que Windows pregunte cada vez.
/// (La instalación en sí la hace FirewallFamiliar-Instalar.exe, creado con Inno Setup.)
/// </summary>
public static class Installer
{
    public const string TaskName = "Firewall Familiar";
    public static readonly string InstallDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Firewall Familiar");
    public static string InstalledExe => Path.Combine(InstallDir, "FirewallFamiliar.exe");


    public static bool IsInstalled => File.Exists(InstalledExe);

    public static bool RunningInstalled =>
        string.Equals(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\'), InstallDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    // ------------------------------------------------------------------
    // Arranque con Windows (tarea programada)
    // ------------------------------------------------------------------

    private static void TryDelete(string path) { try { File.Delete(path); } catch { } }

    public static bool AutostartEnabled => RunSchtasks($"/Query /TN \"{TaskName}\"") == 0;

    public static void SetAutostart(bool enable, string exe)
    {
        if (!enable)
        {
            if (AutostartEnabled) RunSchtasks($"/Delete /TN \"{TaskName}\" /F");
            return;
        }
        // Cualquier usuario que inicie sesión; con los permisos más altos que tenga (sin pregunta de UAC)
        string xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>Abre Firewall Familiar junto al reloj al iniciar sesión.</Description></RegistrationInfo>
              <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT3S</Delay></LogonTrigger></Triggers>
              <Principals><Principal id="Author"><GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>5</Priority>
                <AllowStartOnDemand>true</AllowStartOnDemand>
              </Settings>
              <Actions Context="Author"><Exec><Command>"{System.Security.SecurityElement.Escape(exe)}"</Command><Arguments>--bandeja</Arguments></Exec></Actions>
            </Task>
            """;
        string tmp = Path.Combine(Path.GetTempPath(), "FirewallFamiliar-tarea.xml");
        File.WriteAllText(tmp, xml, Encoding.Unicode);
        try
        {
            int code = RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{tmp}\" /F");
            if (code != 0) throw new InvalidOperationException($"Windows no ha dejado crear la tarea de arranque (código {code}).");
        }
        finally { TryDelete(tmp); }
    }

    private static int RunSchtasks(string args)
    {
        using var p = Process.Start(new ProcessStartInfo("schtasks.exe", args)
        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true })!;
        p.StandardOutput.ReadToEnd();
        p.StandardError.ReadToEnd();
        p.WaitForExit(15000);
        return p.ExitCode;
    }

}
