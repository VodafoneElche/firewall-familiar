using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace FirewallFamiliar.Core;

/// <summary>Una medición de velocidad guardada (diaria o a mano).</summary>
public sealed class SpeedSample
{
    public DateTime Time { get; set; } = DateTime.Now;
    public string Network { get; set; } = "";
    public bool Manual { get; set; }
    public double? Down { get; set; }
    public double? Up { get; set; }
    public double? Ping { get; set; }
    public double? Jitter { get; set; }
    public double? DownLoaded { get; set; }
    public double? UpLoaded { get; set; }
    public double? RouterPing { get; set; }
    /// <summary>Problemas encontrados (vacío = todo bien).</summary>
    public string Problem { get; set; } = "";

    public bool Bad => Problem.Length > 0;
    public string TimeText => $"{Time:dd/MM HH:mm}{(Manual ? " (a mano)" : "")}";
    public string DownText => Mb(Down);
    public string UpText => Mb(Up);
    public string PingText => Ms(Ping) + (Jitter != null ? $" (±{Jitter:0})" : "");
    public string LoadedText => $"{Ms(DownLoaded)} / {Ms(UpLoaded)}";
    public string RouterText => Ms(RouterPing);
    public string StateText => Bad ? "⚠ " + Problem : "✔ Bien";

    private static string Ms(double? v) => v == null ? "?" : $"{v:0} ms";
    private static string Mb(double? v) => v == null ? "?" : $"{v:0} Mbps";

    public static SpeedSample From(SpeedResult r, string network, bool manual) => new()
    {
        Network = network, Manual = manual, Down = r.DownMbps, Up = r.UpMbps, Ping = r.PingMs, Jitter = r.JitterMs,
        DownLoaded = r.DownLoadedPingMs, UpLoaded = r.UpLoadedPingMs, RouterPing = r.RouterPingMs
    };
}

/// <summary>
/// Historial de mediciones (C:\ProgramData\FirewallFamiliar\velocidad.json, las 120 últimas)
/// y qué cuenta como "problema de red". Lo normal de cada PC se saca de sus propias mediciones,
/// porque un portátil por Wi-Fi en otra habitación nunca irá como uno por cable.
/// </summary>
public static class SpeedHistory
{
    private static readonly string FilePath = Path.Combine(RuleStore.Folder, "velocidad.json");
    private static readonly object Lock = new();

    public static List<SpeedSample> Load()
    {
        lock (Lock)
        {
            try
            {
                if (File.Exists(FilePath))
                    return JsonSerializer.Deserialize<List<SpeedSample>>(File.ReadAllText(FilePath)) ?? new();
            }
            catch { }
            return new();
        }
    }

    public static void Add(SpeedSample s)
    {
        lock (Lock)
        {
            var list = Load();
            list.Add(s);
            if (list.Count > 120) list.RemoveRange(0, list.Count - 120);
            try
            {
                Directory.CreateDirectory(RuleStore.Folder);
                string tmp = FilePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(list));
                File.Move(tmp, FilePath, true);
            }
            catch { }
        }
    }

    /// <summary>Lo normal en esta red: la mediana de las últimas mediciones buenas.</summary>
    public static (double? Down, double? Up) Normal(IEnumerable<SpeedSample> history, string network)
    {
        var good = history.Where(h => h.Network == network && !h.Bad && h.Down != null && h.Up != null).TakeLast(10).ToList();
        if (good.Count < 3) return (null, null);
        return (Median(good.Select(g => g.Down!.Value)), Median(good.Select(g => g.Up!.Value)));
    }

    /// <summary>Busca problemas en una medición comparándola con lo normal de esta red.</summary>
    public static string Evaluate(SpeedSample s, IEnumerable<SpeedSample> history)
    {
        var p = new List<string>();
        if (s.Ping == null) p.Add("no se ha podido llegar a Internet (o el servidor de prueba no contesta)");
        if (s.RouterPing == null) p.Add("el router no contesta al ping");
        else if (s.RouterPing > 30) p.Add($"el router tarda {s.RouterPing:0} ms en contestar (lo normal es menos de 5): Wi-Fi débil o router saturado");
        if (s.Ping > 60) p.Add($"latencia alta: {s.Ping:0} ms");
        if (s.Jitter > 30) p.Add($"latencia muy irregular (±{s.Jitter:0} ms): las videollamadas irán a tirones");
        double worstLoaded = Math.Max(s.DownLoaded ?? 0, s.UpLoaded ?? 0);
        if (s.Ping != null && worstLoaded > s.Ping + 200) p.Add($"la línea se atasca al usarla: la latencia sube a {worstLoaded:0} ms");
        var (down, up) = Normal(history, s.Network);
        if (s.Ping != null && down != null && s.Down != null && s.Down < down * 0.4)
            p.Add($"bajada mucho más lenta de lo normal: {s.Down:0} Mbps (lo normal aquí, {down:0})");
        if (s.Ping != null && up != null && s.Up != null && s.Up < up * 0.4)
            p.Add($"subida mucho más lenta de lo normal: {s.Up:0} Mbps (lo normal aquí, {up:0})");
        return string.Join("; ", p);
    }

    private static double Median(IEnumerable<double> v)
    {
        var s = v.OrderBy(x => x).ToList();
        return s.Count % 2 == 1 ? s[s.Count / 2] : (s[s.Count / 2 - 1] + s[s.Count / 2]) / 2;
    }
}
