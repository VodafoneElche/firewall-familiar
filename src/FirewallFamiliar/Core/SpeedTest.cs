using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallFamiliar.Core;

public sealed record SpeedResult(double? RouterPingMs, double? PingMs, double? JitterMs, double? DownMbps, double? UpMbps,
    double? DownLoadedPingMs, double? UpLoadedPingMs, string Note)
{
    private static string Ms(double? v) => v == null ? "?" : $"{v:0} ms";
    private static string Mb(double? v) => v == null ? "?" : v >= 1000 ? $"{v / 1000:0.00} Gbps" : $"{v:0.0} Mbps";

    public string Text =>
        $"Bajada {Mb(DownMbps)} · Subida {Mb(UpMbps)} · Latencia a Internet {Ms(PingMs)} (variación {Ms(JitterMs)})" +
        (DownLoadedPingMs != null || UpLoadedPingMs != null ? $" · Latencia con la línea cargada: bajando {Ms(DownLoadedPingMs)}, subiendo {Ms(UpLoadedPingMs)}" : "") +
        $" · Latencia al router {Ms(RouterPingMs)}" + (Note.Length > 0 ? $". {Note}" : "");
}

/// <summary>
/// Prueba de velocidad SOLO cuando se pulsa el botón. Usa el servidor público de Cloudflare
/// (speed.cloudflare.com), que solo recibe y manda datos de relleno: no se envía nada del PC.
/// La latencia al router se mide con ping, sin salir de casa.
/// </summary>
public static class SpeedTest
{
    private const string Base = "https://speed.cloudflare.com";
    private static readonly HttpClient Http = new(new SocketsHttpHandler { MaxConnectionsPerServer = 8, PooledConnectionLifetime = TimeSpan.FromMinutes(1) })
    { Timeout = TimeSpan.FromSeconds(30) };

    public static async Task<SpeedResult> RunAsync(string gateway, IProgress<string>? progress, CancellationToken cancel = default)
    {
        string note = "";
        double? router = null, ping = null, jitter = null, down = null, up = null, downLoaded = null, upLoaded = null;

        if (gateway.Length > 0)
        {
            progress?.Report("Midiendo la latencia al router...");
            router = await RouterPingAsync(gateway);
        }

        progress?.Report("Midiendo la latencia a Internet...");
        try
        {
            var times = await LatencySamplesAsync(12, cancel);
            if (times.Count >= 3)
            {
                ping = Median(times);
                jitter = times.Zip(times.Skip(1), (a, b) => Math.Abs(a - b)).Average();
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { note = "No se pudo conectar con el servidor de prueba: " + ex.Message; }

        if (ping != null)
        {
            progress?.Report("Midiendo la bajada (unos 8 segundos)...");
            (down, downLoaded) = await MeasureAsync(upload: false, cancel);
            progress?.Report("Midiendo la subida (unos 8 segundos)...");
            (up, upLoaded) = await MeasureAsync(upload: true, cancel);
        }
        if (note.Length == 0) note = "Medido con el Wi-Fi o cable de este PC: con otros aparatos usando Internet saldrá menos";
        return new SpeedResult(router, ping, jitter, down, up, downLoaded, upLoaded, note);
    }

    private static async Task<double?> RouterPingAsync(string gateway)
    {
        try
        {
            using var p = new Ping();
            var list = new List<double>();
            for (int i = 0; i < 5; i++)
            {
                var r = await p.SendPingAsync(gateway, 1000);
                if (r.Status == IPStatus.Success) list.Add(r.RoundtripTime);
            }
            return list.Count > 0 ? Median(list) : null;
        }
        catch { return null; }
    }

    private static async Task<List<double>> LatencySamplesAsync(int n, CancellationToken cancel)
    {
        var list = new List<double>();
        for (int i = 0; i < n + 1; i++)
        {
            var sw = Stopwatch.StartNew();
            using var res = await Http.GetAsync($"{Base}/__down?bytes=0", HttpCompletionOption.ResponseHeadersRead, cancel);
            sw.Stop();
            if (i > 0 && res.IsSuccessStatusCode) list.Add(sw.Elapsed.TotalMilliseconds); // la primera incluye abrir la conexión
        }
        return list;
    }

    /// <summary>4 descargas o subidas a la vez durante unos 8 segundos; se cuentan los bytes de los últimos 6.</summary>
    private static async Task<(double? Mbps, double? LoadedPing)> MeasureAsync(bool upload, CancellationToken cancel)
    {
        const int Streams = 4;
        var total = TimeSpan.FromSeconds(8);
        var warm = TimeSpan.FromSeconds(2);
        long bytes = 0;
        var sw = Stopwatch.StartNew();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        stop.CancelAfter(total + TimeSpan.FromSeconds(2));
        var payload = new byte[4 * 1024 * 1024];
        new Random().NextBytes(payload);

        async Task Worker()
        {
            var buf = new byte[64 * 1024];
            while (sw.Elapsed < total && !stop.IsCancellationRequested)
            {
                try
                {
                    if (upload)
                    {
                        using var content = new CountingContent(payload, n => { if (sw.Elapsed > warm) Interlocked.Add(ref bytes, n); });
                        using var res = await Http.PostAsync($"{Base}/__up", content, stop.Token);
                    }
                    else
                    {
                        using var res = await Http.GetAsync($"{Base}/__down?bytes=25000000", HttpCompletionOption.ResponseHeadersRead, stop.Token);
                        using var s = await res.Content.ReadAsStreamAsync(stop.Token);
                        int read;
                        while ((read = await s.ReadAsync(buf, stop.Token)) > 0)
                        {
                            if (sw.Elapsed > warm) Interlocked.Add(ref bytes, read);
                            if (sw.Elapsed >= total) break;
                        }
                    }
                }
                catch { if (stop.IsCancellationRequested) return; await Task.Delay(200); }
            }
        }

        // Latencia mientras la línea va llena (si sube mucho, las videollamadas y juegos van a tirones)
        async Task<double?> LoadedPing()
        {
            var list = new List<double>();
            await Task.Delay(warm);
            while (sw.Elapsed < total - TimeSpan.FromSeconds(1) && !stop.IsCancellationRequested)
            {
                try
                {
                    var t = Stopwatch.StartNew();
                    using var res = await Http.GetAsync($"{Base}/__down?bytes=0", HttpCompletionOption.ResponseHeadersRead, stop.Token);
                    list.Add(t.Elapsed.TotalMilliseconds);
                }
                catch { }
                await Task.Delay(400);
            }
            return list.Count > 0 ? Median(list) : null;
        }

        var workers = Enumerable.Range(0, Streams).Select(_ => Worker()).ToList();
        var loaded = LoadedPing();
        try { await Task.WhenAll(workers); } catch { }
        double? lp = null;
        try { lp = await loaded; } catch { }
        double seconds = Math.Max(0.5, Math.Min(sw.Elapsed.TotalSeconds, total.TotalSeconds) - warm.TotalSeconds);
        return (bytes > 0 ? bytes * 8 / seconds / 1_000_000 : null, lp);
    }

    private static double Median(List<double> v)
    {
        var s = v.OrderBy(x => x).ToList();
        return s.Count % 2 == 1 ? s[s.Count / 2] : (s[s.Count / 2 - 1] + s[s.Count / 2]) / 2;
    }

    /// <summary>Contenido para la subida que va contando lo que se ha enviado.</summary>
    private sealed class CountingContent : HttpContent
    {
        private readonly byte[] _data;
        private readonly Action<int> _sent;
        public CountingContent(byte[] data, Action<int> sent) { _data = data; _sent = sent; Headers.ContentType = new("application/octet-stream"); }

        protected override async Task SerializeToStreamAsync(System.IO.Stream stream, System.Net.TransportContext? context)
        {
            for (int off = 0; off < _data.Length; off += 64 * 1024)
            {
                int n = Math.Min(64 * 1024, _data.Length - off);
                await stream.WriteAsync(_data.AsMemory(off, n));
                _sent(n);
            }
        }

        protected override bool TryComputeLength(out long length) { length = _data.Length; return true; }
    }
}
