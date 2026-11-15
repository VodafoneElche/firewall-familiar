using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Service;

/// <summary>
/// Archivos trampa (idea que vio Jose en Twitter): en la carpeta de cada usuario se dejan unos
/// archivos ocultos con contraseñas FALSAS (passwords.txt, contraseñas.txt, claves-banco.txt).
/// Nadie de casa tiene por qué abrirlos; los programas que roban contraseñas sí los buscan.
///
/// Cómo se sabe quién los lee: Windows tiene "auditoría de archivos". Se enciende solo para
/// la lectura de estos archivos y Windows apunta en su registro de Seguridad (evento 4663) qué
/// programa los ha abierto, con qué usuario y a qué hora. El servicio lo mira cada 10 segundos.
///
/// Qué se hace:
///  - antivirus (Defender, Trend Micro), el indexador de Windows y el propio Firewall Familiar:
///    es normal, solo se apunta;
///  - un programa FIRMADO (Bloc de notas, Explorador, una copia de seguridad...): aviso urgente
///    por correo, sin cortar Internet;
///  - un programa SIN FIRMA, con firma no válida o que ya se ha borrado a sí mismo: aviso urgente
///    y se pone "Bloquear todo" (se quita con la contraseña desde el icono). Lo eligió Jose.
/// </summary>
internal sealed class TrapWatch
{
    private static readonly string StateFile = Path.Combine(RuleStore.Folder, "trampas.json");

    /// <summary>Subcategoría "Sistema de archivos" de la auditoría (por número: el nombre cambia con el idioma).</summary>
    private static readonly Guid FileSystemAudit = new("0CCE921D-69AE-11D9-BED3-505054503030");

    /// <summary>Sitio (dentro de la carpeta del usuario) y nombre de cada trampa.</summary>
    private static readonly (string Folder, string Name)[] Places =
    {
        ("", "passwords.txt"),
        ("Desktop", "contraseñas.txt"),
        ("Documents", "claves-banco.txt"),
    };

    /// <summary>Programas de script: van firmados por Microsoft, pero los usan mucho los virus.</summary>
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe", "conhost.exe", "msbuild.exe"
    };

    private readonly Action<string, string, string?, int> _log;
    /// <summary>Se llama cuando hay que cortar Internet (programa sin firma).</summary>
    private readonly Action<string> _cut;
    private State _state;
    private int _busy;
    private DateTime _lastPlace = DateTime.MinValue;
    private string? _auditError;
    private readonly Dictionary<string, DateTime> _alerted = new(StringComparer.OrdinalIgnoreCase);

    private sealed class State
    {
        /// <summary>Trampas creadas por nosotros (para no tocar nunca un archivo de verdad del usuario).</summary>
        public HashSet<string> Files { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Último evento del registro de Seguridad ya revisado.</summary>
        public long LastRecord { get; set; } = -1;
    }

    public TrapWatch(Action<string, string, string?, int> log, Action<string> cut)
    {
        _log = log;
        _cut = cut;
        _state = Load();
    }

    public int Count => _state.Files.Count;

    /// <summary>Cada 10 segundos: mira quién ha leído las trampas. Cada 10 minutos: las repone.</summary>
    public void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            if (DateTime.Now - _lastPlace > TimeSpan.FromMinutes(10))
            {
                _lastPlace = DateTime.Now;
                EnsureAudit();
                PlaceTraps();
            }
            CheckEvents();
        }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    // ------------------------------------------------------------------ Auditoría de Windows
    private void EnsureAudit()
    {
        try
        {
            EnablePrivilege();
            uint flags = QueryAudit();
            if ((flags & 1) == 0) // POLICY_AUDIT_EVENT_SUCCESS
            {
                SetAudit(flags | 1);
                _log("Archivos trampa: encendida la auditoría de lectura de archivos de Windows (solo apunta los archivos marcados).", "", null, 0);
            }
            if (_auditError != null) _log("Archivos trampa: la auditoría de Windows ya funciona.", "", null, 0);
            _auditError = null;
        }
        catch (Exception ex)
        {
            if (_auditError != ex.Message)
                _log("⚠ Archivos trampa: no se pudo encender la auditoría de Windows (" + ex.Message + "). Las trampas no avisarán.", "", null, 0);
            _auditError = ex.Message;
        }
    }

    // ------------------------------------------------------------------ Poner las trampas
    private void PlaceTraps()
    {
        int created = 0;
        foreach (var user in StartupItems.Users())
        {
            if (!Directory.Exists(user.Profile)) continue;
            foreach (var (folder, name) in Places)
            {
                string dir = folder.Length == 0 ? user.Profile : Path.Combine(user.Profile, folder);
                if (!Directory.Exists(dir)) continue;
                string path = Path.Combine(dir, name);
                try
                {
                    bool ours = _state.Files.Contains(path);
                    if (File.Exists(path) && !ours) continue; // es un archivo del usuario: no se toca
                    if (!File.Exists(path))
                    {
                        File.WriteAllText(path, FakeContent(name), new System.Text.UTF8Encoding(false));
                        _state.Files.Add(path);
                        created++;
                    }
                    var attr = File.GetAttributes(path);
                    var want = attr | FileAttributes.Hidden | FileAttributes.NotContentIndexed;
                    if (want != attr) File.SetAttributes(path, want);
                    SetReadAudit(path);
                }
                catch (Exception ex) { _log($"⚠ Archivos trampa: no se pudo preparar {path}: {ex.Message}", "", null, 0); }
            }
        }
        _state.Files.RemoveWhere(p => !File.Exists(p) && !Directory.Exists(Path.GetDirectoryName(p)));
        if (created > 0)
            _log($"Archivos trampa: {created} nuevos (en total {_state.Files.Count} vigilados, ocultos, con contraseñas falsas).", "", null, 0);
        Save();
    }

    private static string FakeContent(string name) => name switch
    {
        "claves-banco.txt" =>
            "BANCO\r\nusuario: 48291736Q\r\nclave de acceso: 739128\r\nfirma: 5521\r\n\r\nTARJETA\r\n4539 1488 0343 6467  caduca 09/29  cvv 381\r\n",
        "contraseñas.txt" =>
            "correo: cuentas.casa.familia@gmail.com  /  Verano2019!\r\nnetflix: mismo correo  /  Pelis*2021\r\n" +
            "amazon: mismo correo  /  Compras#4471\r\nwifi casa: MiFibra-7A3C  /  hT9xLq2mZp4v\r\n",
        _ =>
            "email: family.home.accounts@gmail.com  password: Summer2019!\r\nfacebook: same email  pass: Fb_casa_88\r\n" +
            "paypal: same email  pass: Pp#2020casa\r\nsteam: casa_gamer88  pass: St3am!casa\r\n"
    };

    /// <summary>Al desinstalar: se borran las trampas (solo las nuestras).</summary>
    public static void RemoveAll()
    {
        var s = Load();
        foreach (var p in s.Files)
            try
            {
                if (!File.Exists(p)) continue;
                File.SetAttributes(p, FileAttributes.Normal);
                File.Delete(p);
            }
            catch { }
        try { File.Delete(StateFile); } catch { }
    }

    // ------------------------------------------------------------------ Quién las ha leído
    private void CheckEvents()
    {
        if (_state.Files.Count == 0) return;
        if (_state.LastRecord < 0)
        {
            _state.LastRecord = NewestRecord();
            Save();
            return;
        }
        string q = $"*[System[(EventID=4663) and (EventRecordID > {_state.LastRecord})]]";
        long last = _state.LastRecord;
        var hits = new List<(DateTime Time, string File, string App, int Pid, string User)>();
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, q));
            for (EventRecord? r = reader.ReadEvent(); r != null; r = reader.ReadEvent())
                using (r)
                {
                    if (r.RecordId is long id && id > last) last = id;
                    var p = r.Properties;
                    if (p.Count < 12) continue;
                    string file = p[6].Value as string ?? "";
                    if (!_state.Files.Contains(file)) continue;
                    long mask = ToLong(p[9].Value);
                    if ((mask & 1) == 0) continue; // solo lectura del contenido
                    hits.Add((r.TimeCreated ?? DateTime.Now, file, p[11].Value as string ?? "", (int)ToLong(p[10].Value),
                        p[1].Value as string ?? ""));
                }
        }
        catch (EventLogNotFoundException) { }
        catch (UnauthorizedAccessException) { }
        if (last != _state.LastRecord) { _state.LastRecord = last; Save(); }
        foreach (var h in hits) OnRead(h.Time, h.File, h.App, h.Pid, h.User);
    }

    private void OnRead(DateTime time, string file, string app, int pid, string user)
    {
        string exe = Path.GetFileName(app);
        string trap = Path.GetFileName(file);
        string where = Path.GetDirectoryName(file) ?? "";

        // Lo normal: antivirus, indexador, el propio Firewall Familiar
        if (Ignorable(app, out string why))
        {
            if (Once("i|" + app, TimeSpan.FromDays(1)))
                _log($"Archivo trampa {trap} revisado por {why} ({exe}). Es normal.", "", app, pid);
            return;
        }

        var sig = app.Length > 0 && File.Exists(app) ? Signature.CheckNow(app) : new SignatureInfo(SignatureStatus.Desconocida, "", "el programa ya no existe");
        bool signed = sig.Status == SignatureStatus.Valida;
        string who = user.Length > 0 ? $" (usuario {user})" : "";
        string at = $"{(time.Date == DateTime.Today ? "" : $"el {time:dd/MM} ")}a las {time:HH:mm:ss}";

        if (signed)
        {
            if (!Once("f|" + app + "|" + file, TimeSpan.FromDays(1))) return;
            bool script = ScriptHosts.Contains(exe);
            _log($"⚠ ARCHIVO TRAMPA LEÍDO: {exe} (PID {pid}, firmado por {sig.Signer}){who} ha abierto {trap} en {where} {at}. " +
                 (script
                     ? "Es un programa de scripts (lo usan mucho los virus para robar contraseñas): mira qué script se estaba ejecutando. "
                     : "Si no fue nadie de casa a propósito, revisa el PC. ") +
                 "No se corta Internet porque el programa está firmado. Las contraseñas del archivo son falsas.",
                "Alerta", app, pid);
            return;
        }

        if (!Once("u|" + app, TimeSpan.FromHours(1))) return;
        string state = sig.Status switch
        {
            SignatureStatus.SinFirma => "SIN FIRMA",
            SignatureStatus.NoValida => "con firma NO VÁLIDA",
            _ => app.Length > 0 && !File.Exists(app) ? "que ya SE HA BORRADO a sí mismo" : "que no se ha podido comprobar"
        };
        _log($"⚠ POSIBLE ROBO DE CONTRASEÑAS: {(exe.Length > 0 ? exe : "un programa")} (PID {pid}), {state}{who}, ha leído el archivo trampa {trap} " +
             $"en {where} {at}. Se CORTA INTERNET (Bloquear todo) para que no pueda enviar nada. Pasa el antivirus completo y revisa el PC; " +
             "para volver a tener Internet, quita \"Bloquear todo\" desde el icono con la contraseña. Las contraseñas del archivo son falsas.",
            "Alerta", app.Length > 0 ? app : null, pid);
        _cut($"archivo trampa {trap} leído por {(exe.Length > 0 ? exe : "un programa")} {state}");
    }

    private static bool Ignorable(string app, out string why)
    {
        why = "";
        if (app.Length == 0 || app == "-" || app.Equals("System", StringComparison.OrdinalIgnoreCase)) { why = "Windows"; return true; }
        if (Signature.IsOwn(app)) { why = "Firewall Familiar"; return true; }
        string exe = Path.GetFileName(app);
        string sys = Environment.GetFolderPath(Environment.SpecialFolder.System) + "\\";
        if (app.StartsWith(sys, StringComparison.OrdinalIgnoreCase) &&
            (exe.Equals("SearchIndexer.exe", StringComparison.OrdinalIgnoreCase) || exe.Equals("SearchProtocolHost.exe", StringComparison.OrdinalIgnoreCase) ||
             exe.Equals("SearchFilterHost.exe", StringComparison.OrdinalIgnoreCase)))
        { why = "el buscador de Windows"; return true; }

        bool defender = app.Contains(@"\Windows Defender\", StringComparison.OrdinalIgnoreCase) ||
                        app.Contains(@"\Microsoft\Windows Defender Advanced Threat Protection\", StringComparison.OrdinalIgnoreCase);
        bool trend = app.Contains(@"\Trend Micro\", StringComparison.OrdinalIgnoreCase);
        if (!defender && !trend) return false;
        // El antivirus tiene que ser de verdad (firma válida); si no, es alguien haciéndose pasar por él
        if (Signature.CheckNow(app).Status != SignatureStatus.Valida) return false;
        why = defender ? "el antivirus de Windows (Defender)" : "el antivirus Trend Micro";
        return true;
    }

    private bool Once(string key, TimeSpan every)
    {
        if (_alerted.TryGetValue(key, out var t) && DateTime.Now - t < every) return false;
        _alerted[key] = DateTime.Now;
        return true;
    }

    private static long NewestRecord()
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, "*") { ReverseDirection = true });
            using var r = reader.ReadEvent();
            return r?.RecordId ?? 0;
        }
        catch { return 0; }
    }

    private static long ToLong(object? v)
    {
        try
        {
            return v switch
            {
                null => 0,
                string s when s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) => Convert.ToInt64(s[2..], 16),
                string s => long.TryParse(s, out var n) ? n : 0,
                IntPtr p => p.ToInt64(),
                UIntPtr u => (long)u.ToUInt64(),
                ulong u => (long)u,
                _ => Convert.ToInt64(v)
            };
        }
        catch { return 0; }
    }

    // ------------------------------------------------------------------ Estado
    private static State Load()
    {
        try
        {
            if (File.Exists(StateFile))
            {
                var s = JsonSerializer.Deserialize<State>(File.ReadAllText(StateFile));
                if (s != null)
                {
                    s.Files = new HashSet<string>(s.Files, StringComparer.OrdinalIgnoreCase);
                    return s;
                }
            }
        }
        catch { }
        return new State();
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(RuleStore.Folder);
            File.WriteAllText(StateFile, JsonSerializer.Serialize(_state));
        }
        catch { }
    }

    // ------------------------------------------------------------------ Windows (API)
    [StructLayout(LayoutKind.Sequential)]
    private struct AUDIT_POLICY_INFORMATION
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] subCategories, uint count, out IntPtr policy);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditSetSystemPolicy([In] AUDIT_POLICY_INFORMATION[] policy, uint count);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    [DllImport("ntdll.dll")]
    private static extern int RtlAdjustPrivilege(int privilege, bool enable, bool currentThread, out bool wasEnabled);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorSacl(IntPtr sd, out bool present, out IntPtr sacl, out bool defaulted);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint SetNamedSecurityInfoW(string name, int objectType, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);

    private const int SeSecurityPrivilege = 8;

    private static void EnablePrivilege()
    {
        int st = RtlAdjustPrivilege(SeSecurityPrivilege, true, false, out _);
        if (st != 0) throw new InvalidOperationException($"sin permiso de auditoría (0x{st:X8})");
    }

    private static uint QueryAudit()
    {
        if (!AuditQuerySystemPolicy(new[] { FileSystemAudit }, 1, out IntPtr p))
            throw new InvalidOperationException("no se pudo leer la directiva de auditoría (error " + Marshal.GetLastWin32Error() + ")");
        try { return Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(p).AuditingInformation; }
        finally { AuditFree(p); }
    }

    private static void SetAudit(uint flags)
    {
        var info = new[] { new AUDIT_POLICY_INFORMATION { AuditSubCategoryGuid = FileSystemAudit, AuditingInformation = flags } };
        if (!AuditSetSystemPolicy(info, 1))
            throw new InvalidOperationException("no se pudo cambiar la directiva de auditoría (error " + Marshal.GetLastWin32Error() + ")");
    }

    /// <summary>
    /// Marca el archivo para que Windows apunte cada vez que alguien (cualquiera: "Todos") lee su
    /// contenido (0x1 = leer datos). Mirar sus propiedades o verlo en una lista no cuenta.
    /// </summary>
    private static void SetReadAudit(string path)
    {
        EnablePrivilege();
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("S:(AU;SA;0x1;;;WD)", 1, out IntPtr sd, out _))
            throw new InvalidOperationException("error " + Marshal.GetLastWin32Error());
        try
        {
            if (!GetSecurityDescriptorSacl(sd, out _, out IntPtr sacl, out _))
                throw new InvalidOperationException("error " + Marshal.GetLastWin32Error());
            uint err = SetNamedSecurityInfoW(path, 1 /* SE_FILE_OBJECT */, 0x8 /* SACL_SECURITY_INFORMATION */, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
            if (err != 0) throw new InvalidOperationException("no se pudo marcar para auditoría (error " + err + ")");
        }
        finally { LocalFree(sd); }
    }
}
