using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;

namespace FirewallFamiliar.Core;

/// <summary>
/// Algo que se pone en marcha solo: un programa del arranque, una tarea programada, un servicio,
/// una extensión del menú contextual... o un ajuste que suelen cambiar los programas basura
/// (navegador por defecto, página de inicio impuesta, extensiones forzadas).
/// </summary>
public sealed class StartupItem
{
    public string Kind { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>"Todos" o el nombre de la cuenta de Windows.</summary>
    public string User { get; init; } = "Todos";
    /// <summary>Dónde está apuntado (clave del registro, carpeta, tarea...).</summary>
    public string Where { get; init; } = "";
    public string Command { get; init; } = "";
    /// <summary>Archivo que se ejecuta (vacío si es un ajuste).</summary>
    public string Path { get; init; } = "";
    public bool Enabled { get; set; } = true;
    /// <summary>Es un ajuste (navegador, protocolo...), no un programa que se pueda desactivar.</summary>
    public bool IsSetting { get; init; }
    /// <summary>Arranca un script o un comando (PowerShell, VBScript, mshta...).</summary>
    public bool IsScript { get; init; }
    /// <summary>Motivo fijo de sospecha (secuestro de programa, directiva impuesta...).</summary>
    public string? FixedRisk { get; init; }
    internal StartupToggle? Toggle { get; init; }
    public SignatureInfo Signature { get; set; } = SignatureInfo.Pending;

    /// <summary>Identifica la entrada (para saber si es nueva).</summary>
    public string Id => $"{Kind}|{User}|{Where}|{Name}";
    public bool CanToggle => Toggle != null;
    public bool FileMissing => Path.Length > 0 && !IsSetting && !File.Exists(Path);
    public bool IsMicrosoft => Signature.Status == SignatureStatus.Valida &&
                               Signature.Signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

    /// <summary>Por qué hay que mirarlo, o null si parece normal.</summary>
    public string? Risk
    {
        get
        {
            if (FixedRisk != null) return FixedRisk;
            if (IsSetting) return null;
            if (FileMissing) return "el archivo ya no existe: es un resto de un programa desinstalado";
            if (Signature.Status == SignatureStatus.NoValida) return "la firma digital NO es válida";
            if (IsScript) return "arranca un script o un comando (así se esconden muchos virus)";
            if (Signature.Status == SignatureStatus.SinFirma && Suspicion.OddFolder(Path) is { } odd) return "no tiene firma y está en " + odd;
            if (Signature.Status == SignatureStatus.SinFirma) return "no tiene firma digital";
            return null;
        }
    }

    /// <summary>0 = normal, 1 = sin firma, 2 = resto, 3 = revisar.</summary>
    public int Level =>
        FixedRisk != null ? 3 :
        IsSetting ? 0 :
        FileMissing ? 2 :
        Signature.Status == SignatureStatus.NoValida || IsScript ||
        (Signature.Status == SignatureStatus.SinFirma && Suspicion.OddFolder(Path) != null) ? 3 :
        Signature.Status == SignatureStatus.SinFirma ? 1 : 0;

    public string LevelText => Level switch { 3 => "⚠ Revisar", 2 => "Resto", 1 => "Sin firma", _ => "Normal" };
    public string EnabledText => Enabled ? "Sí" : "Desactivado";
    public string SignatureText => IsSetting ? "" : FileMissing ? "(no existe)" : Signature.Short;
    public string RiskText => Risk ?? "";
    /// <summary>Lo que se enseña en la columna "Archivo": el archivo, o el valor si es un ajuste.</summary>
    public string Shown => IsSetting || Path.Length == 0 ? Command : Path;
}

/// <summary>Cómo se desactiva y se vuelve a activar una entrada (siempre de forma reversible).</summary>
internal abstract class StartupToggle
{
    public abstract void Set(bool enable);
}

/// <summary>
/// Lo mismo que hace el Administrador de tareas: no borra la entrada, la marca como
/// desactivada en Explorer\StartupApproved. Se puede volver a activar desde allí también.
/// </summary>
internal sealed class ApprovedToggle : StartupToggle
{
    public required string Hive { get; init; } // "HKLM" o el SID del usuario
    public required string Subkey { get; init; } // Run, Run32 o StartupFolder
    public required string ValueName { get; init; }

    public override void Set(bool enable)
    {
        using var root = Hive == "HKLM"
            ? RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            : RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64).OpenSubKey(Hive, true)
              ?? throw new InvalidOperationException("La cuenta de ese usuario no tiene la sesión abierta.");
        using var key = root.CreateSubKey(StartupItems.ApprovedPath + "\\" + Subkey, true);
        var data = new byte[12];
        data[0] = enable ? (byte)0x02 : (byte)0x03;
        if (!enable) BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 4);
        key.SetValue(ValueName, data, RegistryValueKind.Binary);
    }
}

internal sealed class TaskToggle : StartupToggle
{
    public required string TaskPath { get; init; }
    public override void Set(bool enable) =>
        StartupItems.Run("schtasks.exe", $"/Change /TN \"{TaskPath}\" {(enable ? "/ENABLE" : "/DISABLE")}");
}

internal sealed class ServiceToggle : StartupToggle
{
    public required string ServiceName { get; init; }
    public override void Set(bool enable) =>
        StartupItems.Run("sc.exe", $"config \"{ServiceName}\" start= {(enable ? "auto" : "disabled")}");
}

/// <summary>Las extensiones del menú contextual se bloquean con la lista oficial de Windows ("Shell Extensions\Blocked").</summary>
internal sealed class ShellExtToggle : StartupToggle
{
    public required string Clsid { get; init; }
    public override void Set(bool enable)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.CreateSubKey(StartupItems.BlockedShellExt, true);
        if (enable) key.DeleteValue(Clsid, false);
        else key.SetValue(Clsid, "Bloqueado por Firewall Familiar");
    }
}

/// <summary>
/// Lista todo lo que arranca solo en el PC, para todas las cuentas (las que tienen la sesión
/// abierta, en lo que va en el registro del usuario). No se conecta a Internet: solo lee el
/// registro, las carpetas de Inicio y las tareas programadas.
/// </summary>
public static class StartupItems
{
    internal const string ApprovedPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
    internal const string BlockedShellExt = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";
    private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOncePath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string PolicyRunPath = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";

    private static readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string Sys32 = System.IO.Path.Combine(WinDir, "System32");

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
        { "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe" };
    private static readonly HashSet<string> DllHosts = new(StringComparer.OrdinalIgnoreCase) { "rundll32.exe", "regsvr32.exe" };

    /// <summary>Todo lo que arranca solo. Las firmas se comprueban si <paramref name="signatures"/> es true (tarda más).</summary>
    public static List<StartupItem> Collect(bool signatures = true)
    {
        var list = new List<StartupItem>();
        var users = Users();
        void Try(Action a) { try { a(); } catch { } }
        Try(() => RunKeys(list, users));
        Try(() => StartupFolders(list, users));
        Try(() => Tasks(list));
        Try(() => Services(list));
        Try(() => ContextMenu(list));
        Try(() => Hijacks(list));
        Try(() => Winsock(list));
        Try(() => Browsers(list, users));
        if (signatures)
            foreach (var i in list)
                i.Signature = i.IsSetting || i.Path.Length == 0 ? SignatureInfo.Pending
                    : !File.Exists(i.Path) ? new SignatureInfo(SignatureStatus.Desconocida, "", "no existe")
                    : Core.Signature.CheckNow(i.Path);
        return list;
    }

    /// <summary>Cuentas de Windows del PC: SID, nombre y carpeta. Con "Loaded" las que tienen el registro cargado (sesión abierta).</summary>
    public static List<(string Sid, string Name, string Profile, bool Loaded)> Users()
    {
        var result = new List<(string, string, string, bool)>();
        using var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        var loaded = hku.GetSubKeyNames().ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var profiles = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
        if (profiles == null) return result;
        foreach (var sid in profiles.GetSubKeyNames())
        {
            if (!sid.StartsWith("S-1-5-21-")) continue; // solo personas (no SYSTEM ni servicios)
            using var p = profiles.OpenSubKey(sid);
            string dir = Environment.ExpandEnvironmentVariables(p?.GetValue("ProfileImagePath") as string ?? "");
            if (dir.Length == 0) continue;
            result.Add((sid, System.IO.Path.GetFileName(dir.TrimEnd('\\')), dir, loaded.Contains(sid)));
        }
        return result;
    }

    // ---------------------------------------------------------------- Registro Run
    private static void RunKeys(List<StartupItem> list, List<(string Sid, string Name, string Profile, bool Loaded)> users)
    {
        using var hklm64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var hklm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
        ReadRun(list, hklm64, RunPath, "HKLM", "Run", "Todos", @"HKLM\" + RunPath);
        ReadRun(list, hklm32, RunPath, "HKLM", "Run32", "Todos", @"HKLM\" + RunPath + " (32 bits)");
        ReadRun(list, hklm64, RunOncePath, null, null, "Todos", @"HKLM\" + RunOncePath);
        ReadRun(list, hklm64, PolicyRunPath, null, null, "Todos", @"HKLM\" + PolicyRunPath);
        using var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        foreach (var u in users.Where(u => u.Loaded))
        {
            using var root = hku.OpenSubKey(u.Sid);
            if (root == null) continue;
            ReadRun(list, root, RunPath, u.Sid, "Run", u.Name, @"HKCU\" + RunPath);
            ReadRun(list, root, RunOncePath, null, null, u.Name, @"HKCU\" + RunOncePath);
            ReadRun(list, root, PolicyRunPath, null, null, u.Name, @"HKCU\" + PolicyRunPath);
        }
    }

    private static void ReadRun(List<StartupItem> list, RegistryKey root, string path, string? hive, string? approved, string user, string where)
    {
        using var key = root.OpenSubKey(path);
        if (key == null) return;
        using var appr = approved == null ? null : root.OpenSubKey(ApprovedPath + "\\" + approved);
        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is not string cmd || cmd.Trim().Length == 0) continue;
            var (exe, script) = ExeFromCommand(cmd);
            list.Add(new StartupItem
            {
                Kind = "Inicio de Windows", Name = name.Length > 0 ? name : "(predeterminado)", User = user, Where = where,
                Command = cmd, Path = exe, IsScript = script, Enabled = IsApproved(appr, name),
                Toggle = hive != null && approved != null ? new ApprovedToggle { Hive = hive, Subkey = approved, ValueName = name } : null
            });
        }
    }

    private static bool IsApproved(RegistryKey? approved, string name) =>
        approved?.GetValue(name) is not byte[] { Length: > 0 } b || (b[0] & 1) == 0;

    // ---------------------------------------------------------------- Carpetas de Inicio
    private static void StartupFolders(List<StartupItem> list, List<(string Sid, string Name, string Profile, bool Loaded)> users)
    {
        string common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        ReadFolder(list, common, "Todos", hklm, "HKLM");
        using var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        foreach (var u in users)
        {
            string dir = System.IO.Path.Combine(u.Profile, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");
            using var root = u.Loaded ? hku.OpenSubKey(u.Sid) : null;
            ReadFolder(list, dir, u.Name, root, u.Loaded ? u.Sid : null);
        }
    }

    private static void ReadFolder(List<StartupItem> list, string dir, string user, RegistryKey? root, string? hive)
    {
        if (!Directory.Exists(dir)) return;
        using var appr = root?.OpenSubKey(ApprovedPath + @"\StartupFolder");
        foreach (var file in Directory.GetFiles(dir))
        {
            string name = System.IO.Path.GetFileName(file);
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            string cmd = file;
            if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) && ShortcutTarget(file) is { } t)
                cmd = t.Args.Length > 0 ? $"\"{t.Target}\" {t.Args}" : t.Target;
            var (exe, script) = ExeFromCommand(cmd.StartsWith('"') || !cmd.Contains(' ') ? cmd : $"\"{cmd}\"");
            list.Add(new StartupItem
            {
                Kind = "Carpeta Inicio", Name = System.IO.Path.GetFileNameWithoutExtension(file), User = user, Where = dir,
                Command = cmd, Path = exe, IsScript = script || IsScriptFile(file), Enabled = IsApproved(appr, name),
                Toggle = hive != null ? new ApprovedToggle { Hive = hive, Subkey = "StartupFolder", ValueName = name } : null
            });
        }
    }

    /// <summary>Destino de un acceso directo (.lnk), con el objeto COM de Windows que los lee.</summary>
    private static (string Target, string Args)? ShortcutTarget(string lnk)
    {
        object? shell = null, link = null;
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type == null) return null;
            shell = Activator.CreateInstance(type);
            link = type.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { lnk });
            if (link == null) return null;
            var lt = link.GetType();
            string target = lt.InvokeMember("TargetPath", System.Reflection.BindingFlags.GetProperty, null, link, null) as string ?? "";
            string args = lt.InvokeMember("Arguments", System.Reflection.BindingFlags.GetProperty, null, link, null) as string ?? "";
            return target.Length == 0 ? null : (target, args);
        }
        catch { return null; }
        finally
        {
            if (link != null && System.Runtime.InteropServices.Marshal.IsComObject(link)) System.Runtime.InteropServices.Marshal.ReleaseComObject(link);
            if (shell != null && System.Runtime.InteropServices.Marshal.IsComObject(shell)) System.Runtime.InteropServices.Marshal.ReleaseComObject(shell);
        }
    }

    // ---------------------------------------------------------------- Tareas programadas
    private static void Tasks(List<StartupItem> list)
    {
        string root = System.IO.Path.Combine(Sys32, "Tasks");
        if (!Directory.Exists(root)) return;
        foreach (var file in Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
        {
            try
            {
                var doc = XDocument.Load(file);
                var exec = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Exec");
                if (exec == null) continue; // tareas internas de Windows (COM)
                string command = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value.Trim() ?? "";
                string args = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value.Trim() ?? "";
                if (command.Length == 0) continue;
                var settings = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Settings");
                bool enabled = settings?.Elements().FirstOrDefault(e => e.Name.LocalName == "Enabled")?.Value.Trim() != "false";
                string author = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Author")?.Value.Trim() ?? "";
                string taskPath = file[root.Length..];
                string full = command.Contains(' ') && !command.StartsWith('"') ? $"\"{command}\"" : command;
                if (args.Length > 0) full += " " + args;
                var (exe, script) = ExeFromCommand(full);
                list.Add(new StartupItem
                {
                    Kind = "Tarea programada", Name = taskPath.TrimStart('\\'), Where = "Programador de tareas" + (author.Length > 0 && !author.StartsWith('$') ? $" (autor: {author})" : ""),
                    Command = full, Path = exe, IsScript = script, Enabled = enabled, Toggle = new TaskToggle { TaskPath = taskPath }
                });
            }
            catch { }
        }
    }

    // ---------------------------------------------------------------- Servicios
    private static void Services(List<StartupItem> list)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var services = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services == null) return;
        foreach (var name in services.GetSubKeyNames())
        {
            try
            {
                using var s = services.OpenSubKey(name);
                if (s == null) continue;
                int type = Convert.ToInt32(s.GetValue("Type") ?? 0);
                int start = Convert.ToInt32(s.GetValue("Start") ?? 3);
                if ((type & 0x30) == 0 || (start != 2 && start != 4)) continue; // solo programas (no drivers) automáticos o desactivados
                string image = s.GetValue("ImagePath") as string ?? "";
                if (image.Length == 0) continue;
                string cmd = image;
                var (exe, script) = ExeFromCommand(image);
                if (System.IO.Path.GetFileName(exe).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                {
                    using var p = s.OpenSubKey("Parameters");
                    if ((p?.GetValue("ServiceDll") ?? s.GetValue("ServiceDll")) is string dll)
                    {
                        exe = NormalizePath(Environment.ExpandEnvironmentVariables(dll));
                        cmd = image + "  →  " + dll;
                    }
                }
                string display = s.GetValue("DisplayName") as string ?? "";
                if (display.Length == 0 || display.StartsWith('@')) display = name;
                list.Add(new StartupItem
                {
                    Kind = "Servicio", Name = display == name ? name : $"{display} ({name})", Where = @"HKLM\SYSTEM\CurrentControlSet\Services\" + name,
                    Command = cmd, Path = exe, IsScript = script, Enabled = start == 2, Toggle = new ServiceToggle { ServiceName = name }
                });
            }
            catch { }
        }
    }

    // ---------------------------------------------------------------- Menú contextual
    private static void ContextMenu(List<StartupItem> list)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var classes = hklm.OpenSubKey(@"SOFTWARE\Classes");
        if (classes == null) return;
        using var blocked = hklm.OpenSubKey(BlockedShellExt);
        var blockedSet = (blocked?.GetValueNames() ?? Array.Empty<string>()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var where in new[] { "*", "AllFilesystemObjects", "Directory", @"Directory\Background", "Folder", "Drive" })
        {
            using var handlers = classes.OpenSubKey(where + @"\shellex\ContextMenuHandlers");
            if (handlers == null) continue;
            foreach (var h in handlers.GetSubKeyNames())
            {
                using var hk = handlers.OpenSubKey(h);
                string clsid = hk?.GetValue("") as string ?? "";
                if (!clsid.StartsWith('{')) clsid = h.StartsWith('{') ? h : "";
                if (clsid.Length == 0 || !seen.Add(clsid)) continue;
                using var inproc = classes.OpenSubKey($@"CLSID\{clsid}\InprocServer32");
                string dll = inproc?.GetValue("") as string ?? "";
                if (dll.Length == 0) continue;
                using var ck = classes.OpenSubKey($@"CLSID\{clsid}");
                string title = ck?.GetValue("") as string ?? "";
                list.Add(new StartupItem
                {
                    Kind = "Menú contextual", Name = h.StartsWith('{') && title.Length > 0 ? title : h, Where = $@"HKCR\{where}\shellex\ContextMenuHandlers",
                    Command = dll, Path = NormalizePath(Environment.ExpandEnvironmentVariables(dll.Trim('"'))),
                    Enabled = !blockedSet.Contains(clsid), Toggle = new ShellExtToggle { Clsid = clsid }
                });
            }
        }
    }

    // ---------------------------------------------------------------- Secuestros
    private static void Hijacks(List<StartupItem> list)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using (var ifeo = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"))
            if (ifeo != null)
                foreach (var exe in ifeo.GetSubKeyNames())
                {
                    using var k = ifeo.OpenSubKey(exe);
                    if (k?.GetValue("Debugger") is not string dbg || dbg.Trim().Length == 0) continue;
                    var (path, script) = ExeFromCommand(dbg);
                    list.Add(new StartupItem
                    {
                        Kind = "Secuestro de programa", Name = exe, Where = @"HKLM\...\Image File Execution Options\" + exe,
                        Command = dbg, Path = path, IsScript = script,
                        FixedRisk = $"al abrir {exe} Windows abre en su lugar otro programa (truco de algunos virus para bloquear antivirus o el Administrador de tareas)"
                    });
                }
        using var wl = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        if (wl == null) return;
        void Check(string value, Func<string, bool> isDefault)
        {
            if (wl.GetValue(value) is not string v || isDefault(v.Trim().TrimEnd(',').Trim())) return;
            var (path, script) = ExeFromCommand(v);
            list.Add(new StartupItem
            {
                Kind = "Secuestro de programa", Name = "Winlogon " + value, Where = @"HKLM\...\Winlogon",
                Command = v, Path = path, IsScript = script,
                FixedRisk = "el inicio de sesión de Windows arranca algo distinto de lo normal"
            });
        }
        Check("Shell", v => v.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase));
        Check("Userinit", v => v.Equals(System.IO.Path.Combine(Sys32, "userinit.exe"), StringComparison.OrdinalIgnoreCase) ||
                               v.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase));
    }

    // ---------------------------------------------------------------- Protocolos de red (Winsock)
    private static void Winsock(List<StartupItem> list)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var dlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var cat in new[] { "Catalog_Entries", "Catalog_Entries64" })
        {
            using var k = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\" + cat);
            if (k == null) continue;
            foreach (var e in k.GetSubKeyNames())
            {
                using var ek = k.OpenSubKey(e);
                if (ek?.GetValue("PackedCatalogItem") is not byte[] b) continue;
                int end = Array.IndexOf(b, (byte)0);
                string path = Encoding.Default.GetString(b, 0, end < 0 ? Math.Min(260, b.Length) : end);
                if (path.Length > 0) dlls.Add(path);
            }
        }
        foreach (var cat in new[] { "Catalog_Entries", "Catalog_Entries64" })
        {
            using var k = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\" + cat);
            if (k == null) continue;
            foreach (var e in k.GetSubKeyNames())
            {
                using var ek = k.OpenSubKey(e);
                if (ek?.GetValue("LibraryPath") is string p && p.Length > 0) dlls.Add(p);
            }
        }
        foreach (var d in dlls)
            list.Add(new StartupItem
            {
                Kind = "Protocolo de red", Name = System.IO.Path.GetFileName(d), Where = @"HKLM\SYSTEM\...\WinSock2",
                Command = d, Path = NormalizePath(Environment.ExpandEnvironmentVariables(d))
            });
    }

    // ---------------------------------------------------------------- Navegadores
    private static void Browsers(List<StartupItem> list, List<(string Sid, string Name, string Profile, bool Loaded)> users)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        Policies(list, hklm, "Todos", @"HKLM\");
        using var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        foreach (var u in users.Where(u => u.Loaded))
        {
            using var root = hku.OpenSubKey(u.Sid);
            if (root == null) continue;
            Policies(list, root, u.Name, @"HKCU\");
            using var choice = root.OpenSubKey(@"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice");
            if (choice?.GetValue("ProgId") is string prog)
                list.Add(new StartupItem
                {
                    Kind = "Navegador", Name = "Navegador por defecto", User = u.Name, Where = "Configuración de Windows",
                    Command = BrowserName(prog), IsSetting = true
                });
        }
    }

    private static void Policies(List<StartupItem> list, RegistryKey root, string user, string prefix)
    {
        foreach (var (browser, path) in new[] { ("Chrome", @"SOFTWARE\Policies\Google\Chrome"), ("Edge", @"SOFTWARE\Policies\Microsoft\Edge") })
        {
            using var k = root.OpenSubKey(path);
            if (k == null) continue;
            foreach (var (value, what) in new[] { ("HomepageLocation", "página de inicio"), ("NewTabPageLocation", "página de nueva pestaña"),
                                                  ("DefaultSearchProviderSearchURL", "buscador") })
                if (k.GetValue(value) is string v && v.Length > 0)
                    list.Add(Imposed(browser, what, v, user, prefix + path));
            foreach (var (sub, what) in new[] { ("RestoreOnStartupURLs", "página al abrir"), ("ExtensionInstallForcelist", "extensión instalada a la fuerza") })
            {
                using var s = k.OpenSubKey(sub);
                if (s == null) continue;
                foreach (var n in s.GetValueNames())
                    if (s.GetValue(n) is string v && v.Length > 0)
                        list.Add(Imposed(browser, what, v, user, prefix + path + "\\" + sub));
            }
        }
    }

    private static StartupItem Imposed(string browser, string what, string value, string user, string where) => new()
    {
        Kind = "Navegador", Name = $"{browser}: {what}", User = user, Where = where, Command = value, IsSetting = true,
        FixedRisk = "impuesto por una directiva: lo hacen algunos programas basura para cambiar el navegador sin que se pueda quitar"
    };

    private static string BrowserName(string progId)
    {
        string p = progId.ToLowerInvariant();
        if (p.StartsWith("chromehtml")) return "Google Chrome";
        if (p.StartsWith("msedgehtm")) return "Microsoft Edge";
        if (p.StartsWith("firefox")) return "Firefox";
        if (p.StartsWith("operastable") || p.StartsWith("opera")) return "Opera";
        if (p.StartsWith("bravehtml")) return "Brave";
        return progId;
    }

    // ---------------------------------------------------------------- Utilidades

    /// <summary>
    /// El archivo que ejecuta una línea de comandos. Si es un lanzador de Windows (rundll32, PowerShell,
    /// wscript...), devuelve el archivo que lanza, y "script" = true si es un script o un comando.
    /// </summary>
    public static (string Exe, bool Script) ExeFromCommand(string cmd)
    {
        cmd = Environment.ExpandEnvironmentVariables(cmd.Trim());
        string exe, rest;
        if (cmd.StartsWith('"'))
        {
            int e = cmd.IndexOf('"', 1);
            exe = e > 0 ? cmd[1..e] : cmd.Trim('"');
            rest = e > 0 ? cmd[(e + 1)..] : "";
        }
        else
        {
            var m = Regex.Match(cmd, @"^(.+?\.(exe|com|bat|cmd|dll|scr|vbs|vbe|js|jse|wsf|ps1|hta|lnk))(?=\s|,|$)", RegexOptions.IgnoreCase);
            exe = m.Success ? m.Groups[1].Value : cmd.Split(' ')[0];
            rest = cmd[exe.Length..];
        }
        exe = NormalizePath(exe);
        string file = System.IO.Path.GetFileName(exe);
        if (DllHosts.Contains(file))
        {
            var m = Regex.Match(rest, @"""?([A-Za-z]:\\[^"",]+?\.(dll|ocx|cpl|ax))", RegexOptions.IgnoreCase);
            if (m.Success) return (m.Groups[1].Value, false);
        }
        if (ScriptHosts.Contains(file))
        {
            var m = Regex.Match(rest, @"""?([A-Za-z]:\\[^""]+?\.(vbs|vbe|js|jse|wsf|ps1|bat|cmd|hta))", RegexOptions.IgnoreCase);
            return (m.Success ? m.Groups[1].Value : exe, true);
        }
        return (exe, IsScriptFile(exe));
    }

    private static bool IsScriptFile(string path) =>
        System.IO.Path.GetExtension(path).ToLowerInvariant() is ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" or ".ps1" or ".bat" or ".cmd" or ".hta";

    internal static string NormalizePath(string p)
    {
        p = p.Trim().Trim('"');
        if (p.StartsWith(@"\??\")) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = System.IO.Path.Combine(WinDir, p[12..]);
        else if (p.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = System.IO.Path.Combine(WinDir, p[11..]);
        else if (p.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)) p = System.IO.Path.Combine(WinDir, p);
        if (p.Length > 0 && !System.IO.Path.IsPathRooted(p))
        {
            foreach (var dir in new[] { Sys32, WinDir })
            {
                string c = System.IO.Path.Combine(dir, p);
                if (File.Exists(c)) return c;
                if (System.IO.Path.GetExtension(p).Length == 0 && File.Exists(c + ".exe")) return c + ".exe";
            }
        }
        return p;
    }

    /// <summary>Ejecuta una herramienta de Windows y falla con su mensaje si no sale bien.</summary>
    internal static void Run(string exe, string args)
    {
        var psi = new ProcessStartInfo(System.IO.Path.Combine(Sys32, exe), args)
        {
            CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("No se pudo ejecutar " + exe);
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(15000);
        if (p.ExitCode != 0) throw new InvalidOperationException(output.Trim().Length > 0 ? output.Trim() : $"{exe} terminó con el código {p.ExitCode}");
    }

    /// <summary>Desactiva o vuelve a activar una entrada.</summary>
    public static void SetEnabled(StartupItem item, bool enable)
    {
        if (item.Toggle == null) throw new InvalidOperationException("Esta entrada no se puede desactivar desde aquí.");
        item.Toggle.Set(enable);
        item.Enabled = enable;
    }
}
