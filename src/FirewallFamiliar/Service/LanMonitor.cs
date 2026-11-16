using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Service;

/// <summary>
/// Vigilancia continua de la red de casa (como los sensores de "ping" de los programas de vigilancia
/// de red): cada 5 minutos se mira qué aparatos están encendidos (ARP a toda la red) y cuánto tardan en
/// contestar (ping). Se guarda en vigilancia.json (3 días) para la ficha de cada aparato y el mapa.
/// Los aparatos marcados con "Avisar si deja de contestar" avisan cuando llevan 15 minutos sin contestar.
/// Solo en casa: fuera de casa no se mira nada.
/// </summary>
internal sealed class LanMonitor
{
    private const int MissesToWarn = 3;
    private readonly Action<string, string, string?> _log;
    private readonly Dictionary<string, int> _misses = new();
    private readonly HashSet<string> _warned = new();
    private int _busy;

    public LanMonitor(Action<string, string, string?> log) => _log = log;

    public void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var (gateway, key, _) = RouterCheck.CurrentLocal();
            string? home = RouterCheck.HomeNetwork();
            if (gateway.Length == 0 || key.Length == 0 || (home != null && home != key)) return;

            var found = NetScan.Sweep(gateway).GroupBy(x => x.Ip).Select(g => g.First()).ToList();
            var values = new Dictionary<string, int>();
            Parallel.ForEach(found, new ParallelOptions { MaxDegreeOfParallelism = 64 }, f =>
            {
                int v = LanHistory.NoPing;
                try
                {
                    using var p = new Ping();
                    var r = p.Send(f.Ip, 1000);
                    if (r.Status == IPStatus.Success) v = (int)Math.Min(r.RoundtripTime, 9999);
                }
                catch { }
                lock (values) values[f.Mac] = v;
            });

            var data = LanHistory.Load();
            long slot = LanHistory.Slot(DateTime.Now);
            if (!data.Checked.Contains(slot)) data.Checked.Add(slot);
            foreach (var (mac, v) in values)
            {
                if (!data.Devices.TryGetValue(mac, out var dev)) data.Devices[mac] = dev = new();
                dev[slot] = v;
            }
            LanHistory.Save(data);

            // Aparatos vigilados: avisar si dejan de contestar (y cuando vuelven)
            var book = DeviceBook.Load();
            foreach (var (mac, e) in book.Where(x => x.Value.Watch && x.Value.Network == key))
            {
                string name = e.Name.Length > 0 ? e.Name : e.HostName.Length > 0 ? e.HostName : mac;
                if (values.ContainsKey(mac))
                {
                    _misses[mac] = 0;
                    if (_warned.Remove(mac)) _log($"Red de casa: \"{name}\" vuelve a contestar.", "", null);
                    continue;
                }
                int m = _misses.TryGetValue(mac, out var x) ? x + 1 : 1;
                _misses[mac] = m;
                if (m >= MissesToWarn && _warned.Add(mac))
                    _log($"⚠ Red de casa: \"{name}\" ({e.LastIp}) no contesta desde hace {m * LanHistory.SlotMinutes} minutos. " +
                         "Mira si está encendido y conectado.", "ProblemaRed", null);
            }
        }
        catch { }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }
}
