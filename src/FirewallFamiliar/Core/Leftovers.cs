using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace FirewallFamiliar.Core;

/// <summary>Una carpeta que parece de un programa que ya no está instalado.</summary>
public sealed class LeftoverFolder
{
    public string Path { get; init; } = "";
    public string Name => System.IO.Path.GetFileName(Path);
    public string Where { get; init; } = "";
    public long Size { get; init; }
    public int Files { get; init; }
    public DateTime LastChange { get; init; }
    public string Reason { get; init; } = "";
    /// <summary>Programa basura conocido (SweetLabs, OneLaunch...): se marca aunque esté en uso.</summary>
    public bool KnownJunk { get; init; }
    /// <summary>Un programa en marcha o algo del arranque usa archivos de aquí: no se puede borrar.</summary>
    public bool InUse { get; init; }
    public bool Selected { get; set; }
    public bool CanSelect => !InUse;

    public string SizeText => Models.Format.Bytes(Size);
    public string LastChangeText => LastChange == DateTime.MinValue ? "" : LastChange.ToString("dd/MM/yyyy");
    public string StateText => InUse ? "En uso" : KnownJunk ? "⚠ Programa basura" : "Posible resto";
}

/// <summary>
/// Busca restos de programas desinstalados: carpetas de Archivos de programa, ProgramData y AppData
/// de cada usuario que no pertenecen a ningún programa instalado y llevan meses sin tocarse.
/// Solo las enseña: el borrado lo decide la persona, carpeta a carpeta, y va a la Papelera.
/// </summary>
public static class Leftovers
{
    /// <summary>Si en una carpeta nada ha cambiado en este tiempo, se considera abandonada.</summary>
    public static readonly TimeSpan Quiet = TimeSpan.FromDays(60);
    private const int MaxFilesPerFolder = 3000;

    /// <summary>Programas basura y adware conocidos (por el nombre de su carpeta).</summary>
    private static readonly string[] Junk =
    {
        "sweetlabs", "pokki", "onelaunch", "wavebrowser", "wave browser", "shiftbrowser", "pc app store", "segurazo", "santivirus",
        "bytefence", "webcompanion", "restoro", "reimage", "babylon", "conduit", "mindspark", "searchprotect", "mywebsearch",
        "driver support", "pcoptimizerpro", "pc optimizer pro", "advanced system repair", "systweak", "outbyte", "slimware",
        "browserassistant", "opera browser assistant", "relevantknowledge", "mypc backup", "spigot", "crossrider"
    };

    /// <summary>Carpetas de Windows y genéricas que nunca son restos.</summary>
    private static readonly HashSet<string> Never = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Windows", "Common Files", "Internet Explorer", "WindowsApps", "ModifiableWindowsApps", "Reference Assemblies",
        "MSBuild", "dotnet", "Windows NT", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail",
        "Windows Media Player", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "Windows Sidebar",
        "WindowsPowerShell", "Uninstall Information", "Package Cache", "Packages", "Temp", "Microsoft.NET", "Microsoft Office",
        "Microsoft OneDrive", "OneDrive", "Microsoft Update Health Tools", "PackageManagement", "Application Data", "Desktop",
        "Documents", "Start Menu", "Templates", "USOPrivate", "USOShared", "SoftwareDistribution", "ssh", "regid.1991-06.com.microsoft",
        "Comms", "ConnectedDevicesPlatform", "CrashDumps", "D3DSCache", "PlaceholderTileLogoFolder", "Publishers", "VirtualStore",
        "IconCache", "History", "Programs", "Adobe", "Intel", "NVIDIA", "NVIDIA Corporation", "AMD", "ATI", "Realtek", "Google",
        "Mozilla", "FirewallFamiliar", "Firewall Familiar", "Windows Kits", "WindowsHolographicDevices", "DiagnosticLogCSP",
        "SquirrelTemp", "fontconfig", "pip", "npm", "npm-cache", "Sun", "Oracle", "Java", "WinGet", "Battle.net", "Steam",
        "Package Store", "PeerDistRepub", "WER", "Downloaded Installations", "LocalLow", "Local", "Roaming", "Default", "Public",
        "ProductData", "Desktop.ini", "Windows Live", "Skype", "Teams", "Edge", "EdgeUpdate", "EdgeWebView", "CLR_v4.0", "CLR_v4.0_32"
    };

    /// <summary>Programas instalados (nombre, fabricante y carpetas) según el Panel de control.</summary>
    public static List<(string Name, string Publisher, List<string> Folders)> Installed()
    {
        var list = new List<(string, string, List<string>)>();
        void Read(RegistryKey? root, string path)
        {
            using var k = root?.OpenSubKey(path);
            if (k == null) return;
            foreach (var sub in k.GetSubKeyNames())
            {
                try
                {
                    using var e = k.OpenSubKey(sub);
                    string name = e?.GetValue("DisplayName") as string ?? "";
                    if (name.Length == 0) continue;
                    var folders = new List<string>();
                    foreach (var v in new[] { "InstallLocation", "DisplayIcon", "UninstallString", "InstallSource" })
                        if (e!.GetValue(v) is string s && s.Length > 0)
                        {
                            var (exe, _) = StartupItems.ExeFromCommand(s);
                            string dir = v == "InstallLocation" || v == "InstallSource" ? s.Trim('"') : System.IO.Path.GetDirectoryName(exe) ?? "";
                            if (dir.Length > 3) folders.Add(dir.TrimEnd('\\'));
                        }
                    list.Add((name, e!.GetValue("Publisher") as string ?? "", folders));
                }
                catch { }
            }
        }
        const string u = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        using var hklm64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var hklm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
        Read(hklm64, u);
        Read(hklm32, u);
        using var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        foreach (var sid in hku.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21-") && !s.EndsWith("_Classes")))
        {
            using var root = hku.OpenSubKey(sid);
            Read(root, u);
        }
        return list;
    }

    /// <summary>
    /// Busca restos. <paramref name="inUsePaths"/> son archivos que se están usando (programas en marcha,
    /// cosas del arranque): las carpetas que los contienen nunca se proponen para borrar.
    /// </summary>
    public static List<LeftoverFolder> Find(IEnumerable<string>? inUsePaths = null)
    {
        var installed = Installed();
        var installedFolders = installed.SelectMany(i => i.Folders).Select(f => f.ToLowerInvariant() + "\\").Distinct().ToList();
        var installedNames = installed.SelectMany(i => new[] { Norm(i.Name), Norm(i.Publisher) }).Where(n => n.Length >= 3).Distinct().ToList();

        var used = new List<string>();
        try
        {
            foreach (var p in Process.GetProcesses())
                using (p)
                    try { if (p.MainModule?.FileName is { } f) used.Add(f.ToLowerInvariant()); } catch { }
        }
        catch { }
        if (inUsePaths != null) used.AddRange(inUsePaths.Where(p => p.Length > 0 && File.Exists(p)).Select(p => p.ToLowerInvariant()));

        var roots = new List<(string Dir, string Where)>
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Archivos de programa"),
            (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Archivos de programa (x86)"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ProgramData"),
        };
        foreach (var u in StartupItems.Users())
            foreach (var sub in new[] { @"AppData\Local", @"AppData\Roaming", @"AppData\LocalLow" })
                roots.Add((System.IO.Path.Combine(u.Profile, sub), $"{sub.Replace(@"AppData\", "AppData ")} de {u.Name}"));

        var result = new List<LeftoverFolder>();
        foreach (var (root, where) in roots.DistinctBy(r => r.Dir.ToLowerInvariant()))
        {
            if (root.Length == 0 || !Directory.Exists(root)) continue;
            string[] dirs;
            try { dirs = Directory.GetDirectories(root); } catch { continue; }
            foreach (var dir in dirs)
            {
                try
                {
                    var info = new DirectoryInfo(dir);
                    string name = info.Name;
                    if (Never.Contains(name) || name.StartsWith('.') || name.StartsWith('{') || name.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("Windows", StringComparison.OrdinalIgnoreCase)) continue;
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue; // enlaces: no se siguen
                    string norm = Norm(name);
                    bool junk = Junk.Any(j => norm.Contains(Norm(j)));
                    string lower = dir.ToLowerInvariant() + "\\";
                    bool inUse = used.Any(u => u.StartsWith(lower));
                    if (!junk)
                    {
                        if (inUse) continue;
                        if (installedFolders.Any(f => f.StartsWith(lower) || lower.StartsWith(f))) continue;
                        if (norm.Length < 3 || installedNames.Any(n => n.Contains(norm) || (n.Length >= 4 && norm.Contains(n)))) continue;
                    }
                    var (size, files, last) = Measure(info);
                    if (!junk && (files == 0 || DateTime.Now - last < Quiet)) continue; // vacía o se sigue usando
                    result.Add(new LeftoverFolder
                    {
                        Path = dir, Where = where, Size = size, Files = files, LastChange = last, KnownJunk = junk, InUse = inUse,
                        Reason = junk
                            ? "Es de un programa basura (adware) conocido." + (inUse ? " Está en marcha: desinstálalo o desactívalo en \"Programas que arrancan solos\" y reinicia." : "")
                            : $"No es de ningún programa instalado y no ha cambiado desde hace {(int)(DateTime.Now - last).TotalDays} días."
                    });
                }
                catch { }
            }
        }
        return result.OrderByDescending(r => r.KnownJunk).ThenByDescending(r => r.Size).ToList();
    }

    /// <summary>Tamaño, número de archivos y última modificación (como mucho unos miles de archivos, para no tardar).</summary>
    private static (long Size, int Files, DateTime Last) Measure(DirectoryInfo dir)
    {
        long size = 0;
        int n = 0;
        DateTime last = dir.LastWriteTime;
        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var f in dir.EnumerateFiles("*", opts))
        {
            size += f.Length;
            if (f.LastWriteTime > last) last = f.LastWriteTime;
            if (++n >= MaxFilesPerFolder) { last = DateTime.Now; break; } // muy grande: mejor no proponerla
        }
        return (size, n, last);
    }

    private static string Norm(string s) => new string(s.ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());

    /// <summary>Manda la carpeta a la Papelera (se puede recuperar).</summary>
    public static void ToRecycleBin(LeftoverFolder f)
    {
        if (f.InUse) throw new InvalidOperationException("Está en uso: primero hay que desinstalar o desactivar el programa.");
        Microsoft.VisualBasic.FileIO.FileSystem.DeleteDirectory(f.Path,
            Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs, Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
    }
}
