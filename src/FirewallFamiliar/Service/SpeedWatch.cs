using System;
using System.Linq;
using System.Threading;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Service;

/// <summary>
/// Medición de velocidad diaria (lo pidió Jose): una vez al día, en la red de casa, cuando el PC
/// lleva un rato encendido. Si sale mal se repite a la media hora (un mal momento no es un
/// problema); si vuelve a salir mal, queda en rojo en la ventana y en el registro. Usa el servidor
/// de pruebas de Cloudflare: solo datos de relleno.
/// </summary>
internal sealed class SpeedWatch
{
    private readonly Action<string, string, string?> _log;
    private readonly DateTime _started = DateTime.Now;
    private DateTime _retryAt = DateTime.MaxValue;
    private int _busy;

    public SpeedWatch(Action<string, string, string?> log) => _log = log;

    public void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            if (DateTime.Now - _started < TimeSpan.FromMinutes(15)) return;
            var (gateway, network) = RouterCheck.CurrentNetwork();
            if (gateway.Length == 0 || network.Length == 0 || RouterCheck.HomeNetwork() != network) return; // solo en casa
            var history = SpeedHistory.Load();
            bool retry = DateTime.Now >= _retryAt;
            if (!retry && _retryAt != DateTime.MaxValue) return; // esperando la repetición
            bool doneToday = history.Any(h => !h.Manual && h.Network == network && h.Time.Date == DateTime.Today);
            if (doneToday && !retry) return;

            var r = SpeedTest.RunAsync(gateway, null).GetAwaiter().GetResult();
            var sample = SpeedSample.From(r, network, manual: false);
            string problem = SpeedHistory.Evaluate(sample, history);
            if (problem.Length > 0 && !retry)
            {
                // Primera vez mal: no se guarda como problema todavía, se repite en 30 minutos
                _retryAt = DateTime.Now.AddMinutes(30);
                _log($"Medición de red: algo va mal ({problem}). Se repite en 30 minutos para confirmarlo.", "", null);
                return;
            }
            _retryAt = DateTime.MaxValue;
            sample.Problem = problem;
            SpeedHistory.Add(sample);
            if (problem.Length > 0)
                _log($"⚠ PROBLEMA DE RED: {problem}. Medido dos veces seguidas: bajada {sample.DownText}, subida {sample.UpText}, " +
                     $"latencia {sample.PingText}, router {sample.RouterText}.", "ProblemaRed", null);
            else
                _log($"Medición de red diaria: bajada {sample.DownText}, subida {sample.UpText}, latencia {sample.PingText}, router {sample.RouterText}. Bien.", "", null);
        }
        catch { }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }
}
