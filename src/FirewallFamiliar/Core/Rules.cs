using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FirewallFamiliar.Core;

/// <summary>Qué hacer con un programa o una conexión.</summary>
public enum RuleAction
{
    /// <summary>Sin regla: se aplica el modo general (preguntar o permitir).</summary>
    Preguntar,
    Permitir,
    Bloquear
}

/// <summary>Modo general del cortafuegos, como en Sygate.</summary>
public enum FirewallMode
{
    /// <summary>Aplica las reglas y deja pasar todo lo demás sin preguntar.</summary>
    SinPreguntas,
    /// <summary>Aplica las reglas y pregunta por cada programa nuevo que quiera salir a Internet.</summary>
    Preguntar,
    /// <summary>Bloquea todo el tráfico de red (salvo el interno del propio equipo).</summary>
    BloquearTodo
}

public enum RuleDirection { Saliente, Entrante, Ambas }

public enum RuleProtocol { Cualquiera, TCP, UDP }

/// <summary>Regla para un programa concreto (por la ruta de su ejecutable).</summary>
public sealed class AppRule
{
    public string Path { get; set; } = "";
    public RuleAction Action { get; set; }
    public DateTime Created { get; set; } = DateTime.Now;

    [JsonIgnore]
    public string Name => System.IO.Path.GetFileName(Path);
}

/// <summary>
/// Regla avanzada por puerto, dirección IP, protocolo y/o programa.
/// Se aplican en orden: la primera de la lista tiene más prioridad.
/// </summary>
public sealed class AdvancedRule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "Nueva regla";
    public bool Enabled { get; set; } = true;
    public RuleAction Action { get; set; } = RuleAction.Bloquear;
    public RuleDirection Direction { get; set; } = RuleDirection.Saliente;
    public RuleProtocol Protocol { get; set; } = RuleProtocol.Cualquiera;

    /// <summary>IP o red remota: "1.2.3.4", "192.168.1.0/24". Varias separadas por comas. Vacío = cualquiera.</summary>
    public string RemoteAddresses { get; set; } = "";

    /// <summary>Puertos remotos: "443", "80,443", "6000-7000". Vacío = cualquiera.</summary>
    public string RemotePorts { get; set; } = "";

    /// <summary>Puertos locales (útil para conexiones entrantes). Vacío = cualquiera.</summary>
    public string LocalPorts { get; set; } = "";

    /// <summary>Ruta del programa al que se limita la regla. Vacío = todos los programas.</summary>
    public string AppPath { get; set; } = "";

    [JsonIgnore]
    public string Summary
    {
        get
        {
            var parts = new List<string>();
            parts.Add(Direction switch { RuleDirection.Saliente => "Saliente", RuleDirection.Entrante => "Entrante", _ => "Entrante y saliente" });
            if (Protocol != RuleProtocol.Cualquiera) parts.Add(Protocol.ToString());
            if (RemoteAddresses.Trim().Length > 0) parts.Add("IP " + RemoteAddresses.Trim());
            if (RemotePorts.Trim().Length > 0) parts.Add("puerto remoto " + RemotePorts.Trim());
            if (LocalPorts.Trim().Length > 0) parts.Add("puerto local " + LocalPorts.Trim());
            parts.Add(AppPath.Trim().Length > 0 ? System.IO.Path.GetFileName(AppPath.Trim()) : "todos los programas");
            return string.Join(" · ", parts);
        }
    }

    /// <summary>Comprueba que los campos se entienden. Devuelve el error en lenguaje claro, o null si todo está bien.</summary>
    public string? Validate()
    {
        try { ParseAddresses(RemoteAddresses); }
        catch (FormatException ex) { return "Dirección IP no válida: " + ex.Message; }
        try { ParsePorts(RemotePorts); ParsePorts(LocalPorts); }
        catch (FormatException ex) { return "Puerto no válido: " + ex.Message; }
        if (AppPath.Trim().Length > 0 && !File.Exists(AppPath.Trim()))
            return "No existe el programa: " + AppPath.Trim();
        return null;
    }

    /// <summary>Convierte "1.2.3.4, 10.0.0.0/8" en una lista de (dirección, bits de máscara).</summary>
    public static List<(IPAddress Address, int Prefix)> ParseAddresses(string text)
    {
        var list = new List<(IPAddress, int)>();
        foreach (var raw in Split(text))
        {
            string ipPart = raw;
            int prefix = -1;
            int slash = raw.IndexOf('/');
            if (slash >= 0)
            {
                ipPart = raw[..slash];
                if (!int.TryParse(raw[(slash + 1)..], out prefix)) throw new FormatException(raw);
            }
            if (!IPAddress.TryParse(ipPart, out var ip)) throw new FormatException(raw);
            int max = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            if (prefix < 0) prefix = max;
            if (prefix > max) throw new FormatException(raw);
            list.Add((ip, prefix));
        }
        return list;
    }

    /// <summary>Convierte "80, 443, 6000-7000" en una lista de rangos.</summary>
    public static List<(ushort From, ushort To)> ParsePorts(string text)
    {
        var list = new List<(ushort, ushort)>();
        foreach (var raw in Split(text))
        {
            var bits = raw.Split('-');
            if (bits.Length > 2 || !ushort.TryParse(bits[0].Trim(), out ushort from)) throw new FormatException(raw);
            ushort to = from;
            if (bits.Length == 2 && !ushort.TryParse(bits[1].Trim(), out to)) throw new FormatException(raw);
            if (to < from) throw new FormatException(raw);
            list.Add((from, to));
        }
        return list;
    }

    private static IEnumerable<string> Split(string text) =>
        (text ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim());
}

/// <summary>Todo lo que se guarda en disco.</summary>
public sealed class RuleSet
{
    public FirewallMode Mode { get; set; } = FirewallMode.SinPreguntas;

    /// <summary>Permitir sin preguntar a los programas que forman parte de Windows (C:\Windows).</summary>
    public bool AllowWindowsComponents { get; set; } = true;

    public List<AppRule> Apps { get; set; } = new();
    public List<AdvancedRule> Advanced { get; set; } = new();

    public AppRule? Find(string path) =>
        Apps.FirstOrDefault(a => string.Equals(a.Path, path, StringComparison.OrdinalIgnoreCase));

    public RuleAction ActionFor(string path) => Find(path)?.Action ?? RuleAction.Preguntar;

    /// <summary>Cambia la regla de un programa. "Preguntar" equivale a quitar la regla.</summary>
    public void SetApp(string path, RuleAction action)
    {
        var existing = Find(path);
        if (action == RuleAction.Preguntar)
        {
            if (existing != null) Apps.Remove(existing);
            return;
        }
        if (existing != null) existing.Action = action;
        else Apps.Add(new AppRule { Path = path, Action = action });
    }
}

/// <summary>Carga y guarda las reglas en C:\ProgramData\FirewallFamiliar\reglas.json.</summary>
public static class RuleStore
{
    public static readonly string Folder =
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FirewallFamiliar");

    public static readonly string FilePath = System.IO.Path.Combine(Folder, "reglas.json");

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static RuleSet Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<RuleSet>(File.ReadAllText(FilePath), Options) ?? new RuleSet();
        }
        catch
        {
            // Si el archivo está dañado se guarda una copia y se empieza de cero.
            try { File.Copy(FilePath, FilePath + ".dañado", overwrite: true); } catch { }
        }
        return new RuleSet();
    }

    public static void Save(RuleSet rules)
    {
        Directory.CreateDirectory(Folder);
        string tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(rules, Options));
        File.Move(tmp, FilePath, overwrite: true);
    }
}
