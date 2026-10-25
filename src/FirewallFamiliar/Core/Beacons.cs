using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace FirewallFamiliar.Core;

/// <summary>Un programa que se conecta al mismo sitio una y otra vez a intervalos casi exactos.</summary>
public sealed record Beacon(string App, string Remote, int Count, TimeSpan Interval, DateTime First, DateTime Last, double Regularity);

/// <summary>
/// "Llamar a casa": los programas espía suelen conectarse a su servidor cada X minutos, como un reloj,
/// para recibir órdenes. Aquí se buscan, en el registro de tráfico, programas que abren conexiones nuevas
/// con la misma IP a intervalos muy regulares durante un buen rato.
/// Muchos programas normales también lo hacen (actualizadores, sincronización), así que esto es una pista,
/// no una prueba: se avisa al momento solo si además el programa no tiene firma o vive en una carpeta rara.
/// </summary>
public static class Beacons
{
    private const int MinConnections = 8;
    private static readonly TimeSpan MinInterval = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan MaxInterval = TimeSpan.FromHours(2);
    private static readonly TimeSpan MinSpan = TimeSpan.FromMinutes(30);

    public static List<Beacon> Find(IEnumerable<LogEntry> traffic)
    {
        var result = new List<Beacon>();
        var groups = traffic
            .Where(e => !e.Inbound && e.Outcome == "Permitido" && e.Remote != null && !string.IsNullOrEmpty(e.App) &&
                        IPAddress.TryParse(e.Remote, out var ip) && IpInfo.Special(ip) == null)
            .GroupBy(e => (App: e.App!, Remote: e.Remote!));
        foreach (var g in groups)
        {
            // Varias conexiones casi a la vez cuentan como una
            var times = new List<DateTime>();
            foreach (var t in g.Select(e => e.Time).OrderBy(t => t))
                if (times.Count == 0 || t - times[^1] > TimeSpan.FromSeconds(5)) times.Add(t);
            if (times.Count < MinConnections || times[^1] - times[0] < MinSpan) continue;

            var gaps = times.Zip(times.Skip(1), (a, b) => (b - a).TotalSeconds).OrderBy(x => x).ToList();
            double median = gaps[gaps.Count / 2];
            if (median < MinInterval.TotalSeconds || median > MaxInterval.TotalSeconds) continue;
            double tolerance = Math.Max(median * 0.15, 10);
            double regular = gaps.Count(x => Math.Abs(x - median) <= tolerance) / (double)gaps.Count;
            if (regular < 0.75) continue;
            result.Add(new Beacon(g.Key.App, g.Key.Remote, times.Count, TimeSpan.FromSeconds(median), times[0], times[^1], regular));
        }
        return result.OrderByDescending(b => b.Count).ToList();
    }

    public static string IntervalText(TimeSpan t) =>
        t.TotalMinutes >= 1 ? $"{t.TotalMinutes:0.#} min" : $"{t.TotalSeconds:0} s";
}
