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
    private readonly Dictionary<IPAddress, DateTime> _contacted = new();

    /// <summary>
    /// Este PC ha hablado (o ha intentado hablar) con esa IP. Lo que llegue luego de ella son
    /// respuestas, no un escaneo: por ejemplo al pulsar "Bloquear todo" con conexiones abiertas,
    /// las respuestas del DNS o de las webs llegan a muchos puertos distintos y se bloquean.
    /// </summary>
    public void NoteOutbound(IPAddress remote, DateTime now, int remotePort = 0)
    {
        // El puerto concreto se recuerda siempre, también en casa: lo que vuelva de ese mismo
        // puerto (p. ej. el router contestando a Tailscale en su puerto 52869) es una respuesta.
        if (remotePort > 0)
        {
            _contactedPorts[(remote, remotePort)] = now;
            if (_contactedPorts.Count > 5000)
                foreach (var k in _contactedPorts.Where(kv => now - kv.Value > ContactMemory).Select(kv => kv.Key).ToList())
                    _contactedPorts.Remove(k);
        }
        // En la red de casa los aparatos se hablan entre ellos a menudo: ahí no se aplica,
        // para no esconder un escaneo de verdad desde otro ordenador de casa.
        if (IpInfo.Special(remote) != null) return;
        _contacted[remote] = now;
        if (_contacted.Count > 5000)
            foreach (var k in _contacted.Where(kv => now - kv.Value > ContactMemory).Select(kv => kv.Key).ToList())
                _contacted.Remove(k);
    }

    private readonly Dictionary<(IPAddress, int), DateTime> _contactedPorts = new();

    private static readonly TimeSpan ContactMemory = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Respuesta típica: viene de un puerto de servicio (web 80/443, DNS 53, hora 123...) hacia
    /// un puerto alto de este PC. Un escaneo es al revés: desde un puerto alto hacia los nuestros.
    /// </summary>
    public static bool LooksLikeReply(int remotePort, int localPort) =>
        localPort >= 1024 && remotePort is > 0 and (< 1024 or 5228 or 8080 or 8443 or 3478 or 19302 or 1900 or 3702 or 5351 or 5353 or 5355);

    /// <summary>
    /// Anota un intento de entrada bloqueado. Devuelve el número de puertos probados si
    /// acaba de detectarse un escaneo de ese equipo, o 0 si no.
    /// </summary>
    public int Add(IPAddress remote, int remotePort, int localPort, DateTime now)
    {
        if (LooksLikeReply(remotePort, localPort)) return 0;
        if (_contacted.TryGetValue(remote, out var contacted) && now - contacted < ContactMemory) return 0;
        if (_contactedPorts.TryGetValue((remote, remotePort), out var contactedPort) && now - contactedPort < ContactMemory) return 0;
        // Desde casa, hacia los puertos temporales de este PC (49152 en adelante) y desde un puerto alto:
        // son respuestas tardías a conexiones que abrió este PC (al reiniciarse el servicio o al despertar).
        // Un escaneo de verdad prueba los puertos de servicios (por debajo de 49152).
        if (localPort >= 49152 && remotePort >= 1024 && IpInfo.Special(remote) != null) return 0;
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
