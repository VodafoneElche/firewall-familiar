using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using FirewallFamiliar.Core;
using Microsoft.Win32;

namespace FirewallFamiliar.Service;

/// <summary>
/// Busca señales de que alguien puede estar manejando este PC desde fuera:
///  - programas de control remoto en marcha (AnyDesk, TeamViewer, RustDesk, VNC...);
///  - cualquier programa conectado a los puertos típicos de esos programas (aunque le hayan cambiado el nombre);
///  - conexiones que entran desde Internet hasta un programa que está escuchando;
///  - el Escritorio remoto de Windows activado.
/// Cada cosa se avisa como mucho una vez al día (o cada 6 horas las conexiones), para no llenar de correos.
/// </summary>
internal sealed class RemoteAccessMonitor
{
    /// <summary>Nombre del proceso (sin .exe) → programa.</summary>
    private static readonly Dictionary<string, string> Tools = new(StringComparer.OrdinalIgnoreCase)
    {
        ["anydesk"] = "AnyDesk",
        ["teamviewer"] = "TeamViewer", ["teamviewer_service"] = "TeamViewer", ["tv_w32"] = "TeamViewer", ["tv_x64"] = "TeamViewer",
        ["teamviewerqs"] = "TeamViewer QuickSupport",
        ["rustdesk"] = "RustDesk",
        ["screenconnect.clientservice"] = "ScreenConnect", ["screenconnect.windowsclient"] = "ScreenConnect",
        ["connectwisecontrol.client"] = "ScreenConnect",
        ["srservice"] = "Splashtop", ["srmanager"] = "Splashtop", ["srserver"] = "Splashtop", ["strwinclt"] = "Splashtop",
        ["winvnc"] = "VNC", ["tvnserver"] = "TightVNC", ["vncserver"] = "RealVNC", ["uvnc_service"] = "UltraVNC",
        ["ateraagent"] = "Atera", ["logmein"] = "LogMeIn", ["lmiguardiansvc"] = "LogMeIn", ["lmi_rescue"] = "LogMeIn Rescue",
        ["supremo"] = "Supremo", ["supremoservice"] = "Supremo",
        ["ultraviewer_desktop"] = "UltraViewer", ["ultraviewer_service"] = "UltraViewer",
        ["todesk"] = "ToDesk", ["todesk_service"] = "ToDesk",
        ["quickassist"] = "Asistencia rápida de Windows",
        ["remoting_host"] = "Escritorio remoto de Chrome",
        ["dwrcs"] = "DameWare", ["radmin"] = "Radmin", ["rserver3"] = "Radmin",
        ["rutserv"] = "Remote Utilities", ["rfusclient"] = "Remote Utilities",
        ["aa_v3"] = "Ammyy Admin", ["ammyy_admin"] = "Ammyy Admin",
        ["client32"] = "NetSupport", ["meshagent"] = "MeshCentral",
        ["parsecd"] = "Parsec", ["action1_agent"] = "Action1",
        ["simplehelp"] = "SimpleHelp", ["remotepcservice"] = "RemotePC", ["zohoassist"] = "Zoho Assist",
        ["za_connect"] = "Zoho Assist", ["zaservice"] = "Zoho Assist", ["zohomeeting"] = "Zoho Assist", ["zaupdater"] = "Zoho Assist",
        ["zohourls"] = "Zoho Assist", ["za_session"] = "Zoho Assist",
        ["getscreen"] = "Getscreen", ["dwservice"] = "DWService", ["iperius"] = "Iperius Remote"
    };

    /// <summary>Puertos que usan esos programas.</summary>
    private static readonly Dictionary<int, string> ToolPorts = new()
    {
        [7070] = "AnyDesk", [6568] = "AnyDesk", [5938] = "TeamViewer",
        [5900] = "VNC", [5901] = "VNC", [5500] = "VNC (conexión inversa)",
        [21115] = "RustDesk", [21116] = "RustDesk", [21117] = "RustDesk", [21118] = "RustDesk", [21119] = "RustDesk",
        [8040] = "ScreenConnect", [8041] = "ScreenConnect", [4899] = "Radmin", [6129] = "DameWare",
        [5650] = "Remote Utilities", [5655] = "Remote Utilities"
    };

    private static readonly string StateFile = Path.Combine(RuleStore.Folder, "avisos-control-remoto.json");

    /// <summary>Anota el aviso: texto, programa, PID, IP remota, puerto remoto, puerto local.</summary>
    private readonly Action<string, string?, int, string?, int, int> _alert;
    private readonly Func<int, string> _pathOf;
    private readonly Dictionary<string, DateTime> _lastAlert;
    private readonly HashSet<int> _seenToolPids = new();

    public RemoteAccessMonitor(Action<string, string?, int, string?, int, int> alert, Func<int, string> pathOf)
    {
        _alert = alert;
        _pathOf = pathOf;
        _lastAlert = Load();
    }

    public void Check()
    {
        CheckRemoteDesktop();
        CheckProcesses();
        CheckConnections();
    }

    private bool Due(string key, TimeSpan every)
    {
        if (_lastAlert.TryGetValue(key, out var last) && DateTime.Now - last < every) return false;
        _lastAlert[key] = DateTime.Now;
        foreach (var old in _lastAlert.Where(kv => DateTime.Now - kv.Value > TimeSpan.FromDays(3)).Select(kv => kv.Key).ToList())
            _lastAlert.Remove(old);
        Save();
        return true;
    }

    private void CheckRemoteDesktop()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
            if (k?.GetValue("fDenyTSConnections") is int deny && deny == 0 && Due("rdp", TimeSpan.FromDays(1)))
                _alert("⚠ CONTROL REMOTO: el Escritorio remoto de Windows está ACTIVADO en este PC. Cualquiera de la red que sepa " +
                       "la contraseña de una cuenta puede entrar. Si no lo usáis, desactivadlo en Configuración > Sistema > Escritorio remoto.",
                    null, 0, null, 0, 3389);
        }
        catch { }
    }

    /// <summary>Carpetas típicas de programas de control remoto (por si el .exe tiene un nombre genérico, como "agent.exe").</summary>
    private static readonly (string Folder, string Tool)[] ToolFolders =
    {
        (@"\anydesk", "AnyDesk"), (@"\teamviewer", "TeamViewer"), (@"\rustdesk", "RustDesk"), (@"\zohomeeting", "Zoho Assist"),
        (@"\zoho assist", "Zoho Assist"), (@"\zoho\assist", "Zoho Assist"), (@"\screenconnect", "ScreenConnect"),
        (@"\connectwise", "ScreenConnect"), (@"\splashtop", "Splashtop"), (@"\ultraviewer", "UltraViewer"), (@"\supremo", "Supremo"),
        (@"\todesk", "ToDesk"), (@"\atera", "Atera"), (@"\logmein", "LogMeIn"), (@"\realvnc", "RealVNC"), (@"\tightvnc", "TightVNC"),
        (@"\ultravnc", "UltraVNC"), (@"\remote utilities", "Remote Utilities"), (@"\netsupport", "NetSupport"), (@"\getscreen", "Getscreen"),
        (@"\meshagent", "MeshCentral"), (@"\simplehelp", "SimpleHelp"), (@"\remotepc", "RemotePC"), (@"\dwagent", "DWService")
    };

    private readonly Dictionary<int, string> _paths = new();

    private static string? ToolByFolder(string path)
    {
        foreach (var (folder, tool) in ToolFolders)
            if (path.Contains(folder, StringComparison.OrdinalIgnoreCase)) return tool;
        return null;
    }

    private void CheckProcesses()
    {
        var alive = new HashSet<int>();
        var all = new HashSet<int>();
        foreach (var p in Process.GetProcesses())
            using (p)
            {
                string name;
                int pid;
                try { name = p.ProcessName; pid = p.Id; } catch { continue; }
                all.Add(pid);
                if (!_paths.TryGetValue(pid, out var procPath)) _paths[pid] = procPath = pid <= 4 ? "" : _pathOf(pid);
                if (!Tools.TryGetValue(name, out var tool) && (tool = ToolByFolder(procPath)) == null) continue;
                alive.Add(pid);
                if (!_seenToolPids.Add(pid)) continue;
                string path = _pathOf(pid);
                if (!Due("prog:" + tool + "|" + (path.Length > 0 ? path : name), TimeSpan.FromDays(1))) continue;
                _alert($"⚠ CONTROL REMOTO: {tool} ({name}.exe) está funcionando en este PC (PID {pid}). " +
                       "Con este programa alguien puede ver y manejar el ordenador desde fuera. Si nadie de casa lo ha abierto, " +
                       "desconecta Internet y revisa el PC.", path.Length > 0 ? path : null, pid, null, 0, 0);
            }
        _seenToolPids.IntersectWith(alive);
        foreach (var dead in _paths.Keys.Where(k => !all.Contains(k)).ToList()) _paths.Remove(dead);
    }

    private void CheckConnections()
    {
        List<ConnectionInfo> conns;
        try { conns = ConnectionMonitor.GetAll(); } catch { return; }
        var listening = conns.Where(c => c.IsListening && c.Protocol.StartsWith("TCP")).Select(c => (c.Pid, c.LocalPort)).ToHashSet();
        foreach (var c in conns)
        {
            if (c.IsListening || !c.Protocol.StartsWith("TCP") || c.State != "Establecida") continue;
            if (!IPAddress.TryParse(c.RemoteAddress, out var ip) || IpInfo.Special(ip) != null) continue; // solo Internet
            string path = _pathOf(c.Pid);
            string prog = path.Length > 0 ? ProcessMonitor.FileName(path) : $"PID {c.Pid}";
            bool inbound = listening.Contains((c.Pid, c.LocalPort));
            string ipText = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();

            if (inbound)
            {
                string what = ToolPorts.TryGetValue(c.LocalPort, out var t) ? $" (puerto de {t})" :
                              c.LocalPort == 3389 ? " (Escritorio remoto)" : "";
                if (Due("in:" + (path.Length > 0 ? path : prog) + "|" + c.LocalPort, TimeSpan.FromHours(6)))
                    _alert($"⚠ CONEXIÓN ENTRANTE desde Internet: {ipText} está conectado a {prog} en el puerto {c.LocalPort}{what}. " +
                           "Un PC de casa casi nunca recibe conexiones desde fuera: puede ser alguien entrando.",
                        path.Length > 0 ? path : null, c.Pid, ipText, c.RemotePort, c.LocalPort);
                continue;
            }

            if (ToolPorts.TryGetValue(c.RemotePort, out var tool) && !Tools.ContainsKey(Path.GetFileNameWithoutExtension(path)) && ToolByFolder(path) == null &&
                Due("port:" + (path.Length > 0 ? path : prog) + "|" + c.RemotePort, TimeSpan.FromHours(6)))
                _alert($"⚠ POSIBLE CONTROL REMOTO: {prog} está conectado a {ipText}:{c.RemotePort}, el puerto que usa {tool}. " +
                       "Puede ser un programa de control remoto con otro nombre.",
                    path.Length > 0 ? path : null, c.Pid, ipText, c.RemotePort, c.LocalPort);
        }
    }

    private static Dictionary<string, DateTime> Load()
    {
        try
        {
            if (File.Exists(StateFile))
                return JsonSerializer.Deserialize<Dictionary<string, DateTime>>(File.ReadAllText(StateFile)) ?? new();
        }
        catch { }
        return new();
    }

    private void Save()
    {
        try { File.WriteAllText(StateFile, JsonSerializer.Serialize(_lastAlert)); } catch { }
    }
}
