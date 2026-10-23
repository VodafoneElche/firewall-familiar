using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace FirewallFamiliar.Core;

/// <summary>
/// Instalación sencilla sin instalador aparte: copia el programa a Archivos de programa,
/// crea los accesos directos y una tarea programada que lo abre al iniciar sesión
/// (con permisos de administrador, sin que Windows pregunte cada vez).
/// </summary>
public static class Installer
{
    public const string TaskName = "Firewall Familiar";
    public static readonly string InstallDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Firewall Familiar");
    public static string InstalledExe => Path.Combine(InstallDir, "FirewallFamiliar.exe");

    private static string StartMenuLink => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Firewall Familiar.lnk");
    private static string DesktopLink => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "Firewall Familiar.lnk");

    public static bool IsInstalled => File.Exists(InstalledExe);

    public static bool RunningInstalled =>
        string.Equals(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\'), InstallDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    /// <summary>Copia todos los archivos del programa a la carpeta de instalación.</summary>
    public static void CopyFiles(string fromDir)
    {
        fromDir = Path.GetFullPath(fromDir).TrimEnd('\\');
        Directory.CreateDirectory(InstallDir);
        foreach (var file in Directory.EnumerateFiles(fromDir, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(fromDir, file);
            string dest = Path.Combine(InstallDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Copy(file, dest, true);
        }
    }

    public static void Install()
    {
        if (!RunningInstalled) CopyFiles(AppContext.BaseDirectory);
        SetAutostart(true, InstalledExe);
        CreateShortcut(StartMenuLink, InstalledExe);
        CreateShortcut(DesktopLink, InstalledExe);
    }

    /// <summary>Quita la tarea y los accesos directos, y borra la carpeta cuando el programa se cierre.</summary>
    public static void Uninstall()
    {
        SetAutostart(false, InstalledExe);
        TryDelete(StartMenuLink);
        TryDelete(DesktopLink);
        // No se puede borrar un .exe en marcha: se encarga una ventana de comandos unos segundos después
        Process.Start(new ProcessStartInfo("cmd.exe",
            $"/c timeout /t 4 /nobreak >nul & rmdir /s /q \"{InstallDir}\"")
        { CreateNoWindow = true, UseShellExecute = false });
    }

    private static void TryDelete(string path) { try { File.Delete(path); } catch { } }

    // ------------------------------------------------------------------
    // Arranque con Windows (tarea programada)
    // ------------------------------------------------------------------

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

    // ------------------------------------------------------------------

    private static void CreateShortcut(string link, string target)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type == null) return;
            dynamic shell = Activator.CreateInstance(type)!;
            dynamic sc = shell.CreateShortcut(link);
            sc.TargetPath = target;
            sc.WorkingDirectory = Path.GetDirectoryName(target);
            sc.Description = "Firewall Familiar";
            sc.IconLocation = target + ",0";
            sc.Save();
        }
        catch { }
    }
}
