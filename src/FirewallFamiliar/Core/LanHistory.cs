using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace FirewallFamiliar.Core;

/// <summary>
/// Historial de la vigilancia de la red de casa: cada 5 minutos, qué aparatos estaban encendidos y
/// cuánto tardaron en contestar. Se guardan 3 días en C:\ProgramData\FirewallFamiliar\vigilancia.json.
/// Cada aparato (por su MAC) tiene una lista de "huecos" de 5 minutos con un número:
///   -2 = no contestaba (apagado o fuera de casa), -1 = encendido pero no contesta al ping, 0 o más = milisegundos.
/// </summary>
public static class LanHistory
{
    public const int SlotMinutes = 5;
    public const int Off = -2, NoPing = -1;
    public static readonly TimeSpan Keep = TimeSpan.FromDays(3);
    public static readonly string FilePath = Path.Combine(RuleStore.Folder, "vigilancia.json");
    private static readonly object Lock = new();

    public sealed class Data
    {
        /// <summary>MAC → (hueco → valor). El hueco es el número de 5 minutos desde el 1/1/2000.</summary>
        public Dictionary<string, Dictionary<long, int>> Devices { get; set; } = new();
        /// <summary>Huecos en los que se ha mirado la red (para distinguir "apagado" de "no se miró").</summary>
        public List<long> Checked { get; set; } = new();
    }

    public static long Slot(DateTime t) => (long)((t - new DateTime(2000, 1, 1)).TotalMinutes / SlotMinutes);
    public static DateTime SlotTime(long slot) => new DateTime(2000, 1, 1).AddMinutes(slot * SlotMinutes);

    public static Data Load()
    {
        lock (Lock)
        {
            try
            {
                if (File.Exists(FilePath))
                    return JsonSerializer.Deserialize<Data>(File.ReadAllText(FilePath)) ?? new();
            }
            catch { }
            return new();
        }
    }

    public static void Save(Data d)
    {
        lock (Lock)
        {
            try
            {
                long oldest = Slot(DateTime.Now - Keep);
                d.Checked.RemoveAll(s => s < oldest);
                foreach (var dev in d.Devices.Values)
                    foreach (var k in dev.Keys.Where(k => k < oldest).ToList()) dev.Remove(k);
                foreach (var mac in d.Devices.Where(x => x.Value.Count == 0).Select(x => x.Key).ToList()) d.Devices.Remove(mac);
                string tmp = FilePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(d));
                File.Move(tmp, FilePath, true);
            }
            catch { }
        }
    }

    /// <summary>Resumen de un aparato en las últimas horas, para la ficha.</summary>
    public sealed record Summary(int[] Values, int OnPercent, int AvgMs, int MaxMs, int Checks);

    /// <summary>
    /// Valores de las últimas <paramref name="hours"/> horas (un valor por hueco de 5 minutos):
    /// -3 = no se miró (PC apagado), -2 = apagado, -1 = encendido sin ping, 0+ = ms.
    /// </summary>
    public static Summary? Of(Data d, string mac, int hours = 24)
    {
        int n = hours * 60 / SlotMinutes;
        long last = Slot(DateTime.Now);
        var check = d.Checked.ToHashSet();
        d.Devices.TryGetValue(mac, out var dev);
        var values = new int[n];
        int checks = 0, on = 0;
        var ms = new List<int>();
        for (int i = 0; i < n; i++)
        {
            long s = last - n + 1 + i;
            if (!check.Contains(s)) { values[i] = -3; continue; }
            checks++;
            int v = dev != null && dev.TryGetValue(s, out var x) ? x : Off;
            values[i] = v;
            if (v != Off) on++;
            if (v >= 0) ms.Add(v);
        }
        if (checks == 0) return null;
        return new Summary(values, on * 100 / checks, ms.Count > 0 ? (int)ms.Average() : -1, ms.Count > 0 ? ms.Max() : -1, checks);
    }

    /// <summary>Último valor conocido del aparato (para el mapa): null si no se ha mirado nunca.</summary>
    public static int? Latest(Data d, string mac)
    {
        if (d.Checked.Count == 0) return null;
        long last = d.Checked.Max();
        if (Slot(DateTime.Now) - last > 3) return null; // hace más de 15 minutos: no vale
        return d.Devices.TryGetValue(mac, out var dev) && dev.TryGetValue(last, out var v) ? v : Off;
    }
}
