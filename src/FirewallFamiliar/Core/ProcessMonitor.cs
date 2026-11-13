using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using FirewallFamiliar.Models;

namespace FirewallFamiliar.Core;

/// <summary>Datos de un proceso en un instante dado.</summary>
public sealed class ProcessSnapshot
{
    public int Pid;
    public int ParentPid;
    public string Name = "";
    public string Path = "";
    public string Description = "";
    public string Version = "";
    public string Services = "";
    public long Memory;
    public double CpuPercent;
    public ProcessKind Kind;
    public ImageSource? Icon;
}

/// <summary>
/// Enumera todos los procesos del equipo y decide cuáles son visibles, servicios,
/// componentes de Windows u ocultos (sin ventana y fuera de C:\Windows).
/// </summary>
public sealed class ProcessMonitor
{
    private static readonly string WindowsDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    private readonly Dictionary<int, (long cpu, DateTime when)> _lastCpu = new();
    private readonly ConcurrentDictionary<string, (string desc, string ver, ImageSource? icon)> _fileInfo =
        new(StringComparer.OrdinalIgnoreCase);

    private Dictionary<int, string> _services = new();
    private DateTime _servicesReadAt = DateTime.MinValue;

    /// <summary>Lee la lista de procesos. Pensado para llamarse desde un hilo secundario.</summary>
    public List<ProcessSnapshot> Read()
    {
        if (DateTime.UtcNow - _servicesReadAt > TimeSpan.FromSeconds(15))
        {
            _services = ReadServices();
            _servicesReadAt = DateTime.UtcNow;
        }

        var visible = NativeMethods.GetPidsWithVisibleWindows();
        var parents = NativeMethods.GetParentPids();
        var now = DateTime.UtcNow;
        var result = new List<ProcessSnapshot>();
        var alive = new HashSet<int>();

        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id == 0) continue; // "Proceso inactivo del sistema"
                alive.Add(p.Id);

                var snap = new ProcessSnapshot { Pid = p.Id, Name = p.ProcessName };
                parents.TryGetValue(p.Id, out snap.ParentPid);
                try { snap.Memory = p.WorkingSet64; } catch { }

                snap.Path = p.Id == 4 ? "" : NativeMethods.GetProcessPath(p.Id) ?? "";
                _services.TryGetValue(p.Id, out var svc);
                snap.Services = svc ?? "";

                snap.Kind =
                    p.Id == 4 || snap.Path.Length == 0 ? ProcessKind.Sistema :
                    svc != null ? ProcessKind.Servicio :
                    visible.Contains(p.Id) ? ProcessKind.Ventana :
                    snap.Path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase) ? ProcessKind.Sistema :
                    ProcessKind.Oculto;

                if (p.Id == 4) snap.Description = "Núcleo de Windows";


                long cpu = NativeMethods.GetProcessCpuTime(p.Id);
                if (cpu >= 0 && _lastCpu.TryGetValue(p.Id, out var last))
                {
                    double wall = (now - last.when).TotalMilliseconds * 10_000; // en unidades de 100 ns
                    if (wall > 0)
                        snap.CpuPercent = Math.Max(0, (cpu - last.cpu) / wall / Environment.ProcessorCount * 100);
                }
                if (cpu >= 0) _lastCpu[p.Id] = (cpu, now);

                result.Add(snap);
            }
        }

        // Descripción, versión e icono de cada programa. La primera vez son muchos archivos a la vez:
        // se leen en paralelo (luego quedan guardados y ya no cuesta nada).
        var missing = result.Where(s => s.Path.Length > 0 && !_fileInfo.ContainsKey(s.Path))
                            .Select(s => s.Path).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (missing.Count > 0)
            System.Threading.Tasks.Parallel.ForEach(missing, new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = 4 },
                path => _fileInfo.GetOrAdd(path, ReadFileInfo));
        foreach (var snap in result)
        {
            if (snap.Path.Length == 0) continue;
            var info = _fileInfo.GetOrAdd(snap.Path, ReadFileInfo);
            snap.Description = info.desc;
            snap.Version = info.ver;
            snap.Icon = info.icon;
        }

        ReclassifyHelpers(result);

        foreach (var dead in _lastCpu.Keys.Where(k => !alive.Contains(k)).ToList())
            _lastCpu.Remove(dead);

        return result;
    }

    /// <summary>
    /// Muchos programas (Chrome, Brave, Edge, Teams, Discord...) abren varios procesos sin ventana
    /// para pestañas, extensiones o actualizaciones. No son "ocultos" de verdad: pertenecen a un
    /// programa que el usuario ve. Se marcan como "Segundo plano" si:
    ///  - son el mismo ejecutable que un programa con ventana, o
    ///  - están en la misma carpeta que un programa con ventana, o
    ///  - los ha abierto (directa o indirectamente) un programa con ventana que no es de Windows.
    /// El Explorador de Windows no cuenta como "padre", porque abre todo lo que arranca con el equipo,
    /// que es justo lo que interesa vigilar.
    /// </summary>
    private static void ReclassifyHelpers(List<ProcessSnapshot> all)
    {
        var byPid = all.ToDictionary(s => s.Pid);
        var visibleApps = all.Where(s => s.Kind == ProcessKind.Ventana &&
                                         !s.Path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase)).ToList();
        var visiblePids = visibleApps.Select(s => s.Pid).ToHashSet();
        var visiblePaths = visibleApps.Select(s => s.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Solo carpetas de programas instalados: no vale el Escritorio, Descargas o Temp,
        // porque ahí un proceso oculto sí sería sospechoso.
        var visibleDirs = visibleApps.Select(s => System.IO.Path.GetDirectoryName(s.Path) ?? "")
                                     .Where(IsInstallDir).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var s in all)
        {
            if (s.Kind != ProcessKind.Oculto) continue;

            if (visiblePaths.Contains(s.Path) || visibleDirs.Contains(System.IO.Path.GetDirectoryName(s.Path) ?? ""))
            {
                s.Kind = ProcessKind.SegundoPlano;
                continue;
            }

            // Subir por la cadena de padres (máximo 6 niveles, por si hay ciclos de PIDs reutilizados)
            int parent = s.ParentPid;
            for (int i = 0; i < 6 && parent > 4 && byPid.TryGetValue(parent, out var ps); i++)
            {
                if (visiblePids.Contains(parent)) { s.Kind = ProcessKind.SegundoPlano; break; }
                parent = ps.ParentPid;
            }
        }
    }

    private static bool IsInstallDir(string dir) =>
        (dir.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase) ||
         dir.Contains(@"\AppData\Local\", StringComparison.OrdinalIgnoreCase)) &&
        !dir.Contains(@"\Temp", StringComparison.OrdinalIgnoreCase);

    /// <summary>PID → nombres de los servicios de Windows que corren en ese proceso.</summary>
    private static Dictionary<int, string> ReadServices()
    {
        // Preguntando directamente al administrador de servicios de Windows (instantáneo).
        // WMI, que era lo de antes, tarda varios segundos la primera vez: queda solo de reserva.
        // Primero con los servicios de cada usuario (0x40); si esta versión de Windows no lo acepta, sin ellos.
        var fast = ReadServicesScm(0x30 | 0x40) ?? ReadServicesScm(0x30);
        if (fast != null) return fast;
        var map = new Dictionary<int, string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DisplayName, ProcessId FROM Win32_Service WHERE ProcessId > 0");
            foreach (ManagementObject s in searcher.Get())
            {
                using (s)
                {
                    int pid = Convert.ToInt32(s["ProcessId"]);
                    string name = s["DisplayName"]?.ToString() ?? "";
                    map[pid] = map.TryGetValue(pid, out var prev) ? prev + ", " + name : name;
                }
            }
        }
        catch
        {
            // Si WMI falla, simplemente no se marcan servicios.
        }
        return map;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ENUM_SERVICE_STATUS_PROCESS
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode,
            CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool EnumServicesStatusExW(IntPtr scm, int infoLevel, uint serviceType, uint serviceState,
        IntPtr buffer, uint bufSize, out uint bytesNeeded, out uint servicesReturned, ref uint resumeHandle, string? groupName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    /// <summary>PID → servicios, con la API del administrador de servicios. null si falla.</summary>
    private static Dictionary<int, string>? ReadServicesScm(uint types)
    {
        IntPtr scm = OpenSCManagerW(null, null, 0x0004 /* SC_MANAGER_ENUMERATE_SERVICE */);
        if (scm == IntPtr.Zero) return null;
        IntPtr buf = IntPtr.Zero;
        try
        {
            var map = new Dictionary<int, string>();
            uint size = 256 * 1024, resume = 0;
            buf = Marshal.AllocHGlobal((int)size);
            int entry = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
            while (true)
            {
                // SERVICE_ACTIVE (1)
                bool ok = EnumServicesStatusExW(scm, 0, types, 1, buf, size, out uint needed, out uint count, ref resume, null);
                int err = ok ? 0 : Marshal.GetLastWin32Error();
                if (!ok && err != 234 /* ERROR_MORE_DATA */) return null;
                for (int i = 0; i < count; i++)
                {
                    var s = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(buf + i * entry);
                    if (s.ProcessId == 0) continue;
                    int pid = (int)s.ProcessId;
                    string name = Marshal.PtrToStringUni(s.DisplayName) ?? "";
                    map[pid] = map.TryGetValue(pid, out var prev) ? prev + ", " + name : name;
                }
                if (ok) return map;
                if (count == 0)
                {
                    // No cabía ni uno: buffer más grande
                    if (needed <= size) return null;
                    Marshal.FreeHGlobal(buf);
                    size = needed + 4096;
                    buf = Marshal.AllocHGlobal((int)size);
                }
            }
        }
        catch { return null; }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            CloseServiceHandle(scm);
        }
    }

    private static (string, string, ImageSource?) ReadFileInfo(string path)
    {
        string desc = "", ver = "";
        try
        {
            var v = FileVersionInfo.GetVersionInfo(path);
            desc = v.FileDescription ?? "";
            ver = v.FileVersion ?? "";
        }
        catch { }
        return (desc, ver, LoadIcon(path));
    }

    public static ImageSource? LoadIcon(string path)
    {
        try
        {
            var info = new NativeMethods.SHFILEINFO();
            NativeMethods.SHGetFileInfo(path, 0, ref info, (uint)Marshal.SizeOf(info),
                NativeMethods.SHGFI_ICON | NativeMethods.SHGFI_LARGEICON);
            if (info.hIcon == IntPtr.Zero) return null;
            try
            {
                var img = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, Int32Rect.Empty,
                    BitmapSizeOptions.FromEmptyOptions());
                img.Freeze(); // permite usarla desde el hilo de la interfaz
                return img;
            }
            finally { NativeMethods.DestroyIcon(info.hIcon); }
        }
        catch { return null; }
    }

    /// <summary>Nombre corto de una ruta, para mostrar.</summary>
    public static string FileName(string path) => string.IsNullOrEmpty(path) ? "" : System.IO.Path.GetFileName(path);
}
