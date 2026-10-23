using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace FirewallFamiliar.Core;

/// <summary>
/// Detecta escaneos de puertos: cuando un mismo equipo de fuera intenta entrar por muchos
/// puertos distintos en poco tiempo (como quien prueba todas las puertas de una casa).
/// Los aparatos de casa que buscan impresoras o consolas usan siempre los mismos pocos
/// puertos, así que no cuentan como escaneo.
/// </summary>
public sealed class ScanDetector
{
    /// <summary>Puertos distintos en la ventana de tiempo para considerarlo escaneo.</summary>
    public int Threshold { get; set; } = 10;
    public TimeSpan Window { get; set; } = TimeSpan.FromSeconds(60);
    /// <summary>Tras avisar de un equipo, no se repite el aviso durante este tiempo.</summary>
    public TimeSpan Quiet { get; set; } = TimeSpan.FromMinutes(10);

    private readonly Dictionary<IPAddress, List<(DateTime Time, int Port)>> _hits = new();
    private readonly Dictionary<IPAddress, DateTime> _alerted = new();

    /// <summary>
    /// Anota un intento de entrada bloqueado. Devuelve el número de puertos probados si
    /// acaba de detectarse un escaneo de ese equipo, o 0 si no.
    /// </summary>
    public int Add(IPAddress remote, int localPort, DateTime now)
    {
        if (!_hits.TryGetValue(remote, out var list)) _hits[remote] = list = new();
        list.Add((now, localPort));
        list.RemoveAll(h => now - h.Time > Window);

        // Limpieza de vez en cuando para no acumular memoria
        if (_hits.Count > 2000)
            foreach (var key in _hits.Where(kv => kv.Value.Count == 0 || now - kv.Value[^1].Time > Window).Select(kv => kv.Key).ToList())
                _hits.Remove(key);

        int ports = list.Select(h => h.Port).Distinct().Count();
        if (ports < Threshold) return 0;
        if (_alerted.TryGetValue(remote, out var last) && now - last < Quiet) return 0;
        _alerted[remote] = now;
        return ports;
    }

    /// <summary>Puertos que ha probado un equipo en la última ventana de tiempo (para el aviso).</summary>
    public IReadOnlyList<int> PortsFrom(IPAddress remote) =>
        _hits.TryGetValue(remote, out var list) ? list.Select(h => h.Port).Distinct().OrderBy(p => p).ToList() : Array.Empty<int>();
}
