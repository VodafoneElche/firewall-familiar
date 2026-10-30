using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Service;

/// <summary>
/// Vigilante del sistema (idea de Wise Care 365, hecha a nuestra manera y sin Internet):
///  - cada 2 minutos mira si algo NUEVO se ha puesto a arrancar solo (inicio, tareas, servicios,
///    menú contextual, secuestros de programas, protocolos de red, directivas del navegador) y avisa;
///    urgente (correo del SOC) si no tiene firma, está en una carpeta rara o es un script;
///  - cada 30 minutos hace el chequeo de seguridad y avisa si algo pasa de bien a mal;
///  - cada 6 horas mira la salud de los discos y avisa si alguno puede fallar.
/// Lo que ya había el primer día no se avisa: solo se apunta como conocido.
/// </summary>
internal sealed class SystemWatch
{
    private static readonly string StateFile = Path.Combine(RuleStore.Folder, "vigilante.json");

    private readonly Action<string, string, string?> _log;
    private State _state;
    private int _busy;
    private int _ticks;
    private DateTime _lastDisks = DateTime.MinValue;
    private readonly Dictionary<string, int> _badCount = new();

    private sealed class State
    {
        /// <summary>Entradas de arranque conocidas: Id → comando.</summary>
        public Dictionary<string, string> Startup { get; set; } = new();
        /// <summary>Usuarios cuyo registro ya se ha visto alguna vez.</summary>
        public HashSet<string> Users { get; set; } = new();
        public Dictionary<string, bool> Checks { get; set; } = new();
        /// <summary>Último problema avisado de cada disco, y cuándo.</summary>
        public Dictionary<string, string> Disks { get; set; } = new();
        public Dictionary<string, DateTime> DiskAlerted { get; set; } = new();
        public DateTime LowSpaceWarned { get; set; }
        public bool Initialized { get; set; }
    }

    public SystemWatch(Action<string, string, string?> log)
    {
        _log = log;
        _state = Load();
    }

    public void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            CheckStartup();
            if (_ticks++ % 15 == 0) CheckSecurity();
            if (DateTime.Now - _lastDisks > TimeSpan.FromHours(6))
            {
                _lastDisks = DateTime.Now;
                CheckDisks();
            }
            Save();
        }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    // ------------------------------------------------------------------ Arranque
    private void CheckStartup()
    {
        var items = StartupItems.Collect(signatures: false);
        var loaded = StartupItems.Users().Where(u => u.Loaded).Select(u => u.Name).ToList();
        bool first = !_state.Initialized;
        // Un usuario que abre sesión por primera vez desde que hay vigilante: lo suyo es "lo de siempre"
        var newUsers = loaded.Where(u => !_state.Users.Contains(u)).ToHashSet();

        foreach (var item in items)
        {
            string id = item.Id;
            bool known = _state.Startup.TryGetValue(id, out var before);
            _state.Startup[id] = item.Command;
            if (first || newUsers.Contains(item.User)) continue;
            if (known && before == item.Command) continue;
            Report(item, known ? before : null);
        }

        // Se olvida lo que ya no existe, salvo lo de usuarios que ahora no tienen la sesión abierta
        var present = items.Select(i => i.Id).ToHashSet();
        foreach (var id in _state.Startup.Keys.ToList())
        {
            string user = id.Split('|')[1];
            if (!present.Contains(id) && (user == "Todos" || loaded.Contains(user))) _state.Startup.Remove(id);
        }
        foreach (var u in loaded) _state.Users.Add(u);
        _state.Initialized = true;
    }

    private void Report(StartupItem item, string? before)
    {
        string what = $"{item.Kind} \"{item.Name}\"{(item.User != "Todos" ? $" (de {item.User})" : "")}";
        if (item.IsSetting)
        {
            if (item.Risk != null)
                _log($"⚠ CAMBIO EN EL NAVEGADOR: {what}: {item.Command}. Está {item.Risk}.", "Sospechoso", null);
            else
                _log($"Cambio: {what} es ahora {item.Command}{(before != null ? $" (antes {before})" : "")}.", "Arranque", null);
            return;
        }
        if (item.Path.Length > 0 && File.Exists(item.Path)) item.Signature = Signature.CheckNow(item.Path);
        if (item.IsMicrosoft && item.Risk == null) return; // cosas de Windows (actualizaciones): no se apuntan
        string verb = before == null ? "se ha añadido" : "ha cambiado";
        bool urgent = item.Level >= 3 ||
                      (item.Level == 1 && !item.Path.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase));
        if (urgent)
            _log($"⚠ NUEVO PROGRAMA QUE ARRANCA SOLO: {what} {verb} y arranca {item.Path}: {item.Risk}. " +
                 "Si no lo has instalado tú, desactívalo en Limpieza > Programas que arrancan solos.", "Sospechoso", item.Path);
        else
            _log($"Arranque: {what} {verb}: {item.Path} ({(item.FileMissing ? "el archivo no existe" : item.Signature.Short)}).",
                 "Arranque", item.Path.Length > 0 ? item.Path : null);
    }

    // ------------------------------------------------------------------ Chequeo de seguridad
    private void CheckSecurity()
    {
        foreach (var f in SecurityCheck.Run())
        {
            bool had = _state.Checks.TryGetValue(f.Key, out bool wasOk);
            if (!had)
            {
                _state.Checks[f.Key] = f.Ok;
                if (!f.Ok) _log($"Chequeo de seguridad: {f.Name}: {f.Text}", "", null);
                continue;
            }
            if (f.Ok)
            {
                _badCount.Remove(f.Key);
                if (!wasOk) _log($"Chequeo de seguridad: {f.Name} vuelve a estar bien. {f.Text}", "", null);
                _state.Checks[f.Key] = true;
                continue;
            }
            if (!wasOk) continue;
            // Dos veces seguidas (una hora), por si es un momento raro al encender el PC
            int n = _badCount[f.Key] = _badCount.GetValueOrDefault(f.Key) + 1;
            if (n < 2) continue;
            _badCount.Remove(f.Key);
            _state.Checks[f.Key] = false;
            _log($"⚠ CHEQUEO DE SEGURIDAD: {f.Name}: {f.Text}", "Alerta", null);
        }
    }

    // ------------------------------------------------------------------ Discos
    private void CheckDisks()
    {
        foreach (var d in DiskHealth.Check())
        {
            string key = d.Model + "|" + d.Id;
            string? problem = d.Problem;
            if (problem == null) { _state.Disks.Remove(key); continue; }
            bool same = _state.Disks.TryGetValue(key, out var before) && before == problem;
            bool recent = _state.DiskAlerted.TryGetValue(key, out var when) && DateTime.Now - when < TimeSpan.FromDays(7);
            _state.Disks[key] = problem;
            if (same && recent) continue;
            _state.DiskAlerted[key] = DateTime.Now;
            _log($"⚠ DISCO EN PELIGRO: {d.Model} ({d.Type}, {d.SizeText}): {problem}. " +
                 "Haz cuanto antes una copia de las fotos y documentos importantes.", "Alerta", null);
        }
        var low = DiskHealth.Volumes().Where(v => v.Low).ToList();
        if (low.Count > 0 && DateTime.Now - _state.LowSpaceWarned > TimeSpan.FromDays(1))
        {
            _state.LowSpaceWarned = DateTime.Now;
            _log("Poco espacio libre: " + string.Join("; ", low.Select(v => v.Text)), "", null);
        }
    }

    // ------------------------------------------------------------------ Estado
    private static State Load()
    {
        try
        {
            if (File.Exists(StateFile))
                return JsonSerializer.Deserialize<State>(File.ReadAllText(StateFile)) ?? new State();
        }
        catch { }
        return new State();
    }

    private void Save()
    {
        try
        {
            string tmp = StateFile + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_state));
            File.Move(tmp, StateFile, true);
        }
        catch { }
    }
}
