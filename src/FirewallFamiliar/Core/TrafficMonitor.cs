using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace FirewallFamiliar.Core;

/// <summary>Bytes enviados y recibidos por un proceso.</summary>
public sealed class ProcessTraffic
{
    public long BytesIn;
    public long BytesOut;
}

/// <summary>
/// Escucha en tiempo real los eventos de red del kernel de Windows (ETW).
/// Cada vez que un programa envía o recibe datos por TCP o UDP, Windows emite un evento
/// con el PID del programa y el número de bytes. Aquí se suman por programa.
/// Solo observa: no bloquea ni modifica nada.
/// </summary>
public sealed class TrafficMonitor : IDisposable
{
    private readonly object _lock = new();
    private readonly Dictionary<int, ProcessTraffic> _perProcess = new();
    private long _totalIn;
    private long _totalOut;
    private TraceEventSession? _session;
    private Task? _task;

    /// <summary>Se lanza si el monitor no puede arrancar o se detiene con error.</summary>
    public event Action<string>? Error;

    public bool IsRunning { get; private set; }

    public long TotalIn => Interlocked.Read(ref _totalIn);
    public long TotalOut => Interlocked.Read(ref _totalOut);

    private const string OwnSessionName = "FirewallFamiliar-Trafico";
    private static readonly Guid KernelNetwork = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private static readonly HashSet<int> SendIds = new() { 10, 26, 42, 58 };    // TCP y UDP, IPv4 e IPv6
    private static readonly HashSet<int> RecvIds = new() { 11, 27, 43, 59 };

    public void Start()
    {
        if (!(TraceEventSession.IsElevated() ?? false))
        {
            Error?.Invoke("Hace falta ejecutar como administrador para ver el tráfico por programa.");
            return;
        }
        // Primero, una sesión de eventos propia: nadie nos la puede quitar. El "NT Kernel Logger"
        // es único en todo Windows y algunos programas (antivirus, herramientas de empresa,
        // monitores de red) lo cogen para ellos; entonces el detalle por programa se perdía.
        string? own = StartOwnSession();
        if (own == null) return;
        string? kernel = StartKernelSession();
        if (kernel == null) return;
        IsRunning = false;
        Error?.Invoke($"No se pudo iniciar el monitor de tráfico: {own} / {kernel}");
    }

    /// <summary>
    /// Dirección de un evento de Microsoft-Windows-Kernel-Network. En IPv4 llega como un número
    /// (los 4 bytes en orden de red), no como texto: sin convertirlo salían cosas como "-594763870"
    /// (que es 162.159.140.220).
    /// </summary>
    public static System.Net.IPAddress? EtwAddress(object? v)
    {
        try
        {
            switch (v)
            {
                case null: return null;
                case System.Net.IPAddress a: return a;
                case int i: return new System.Net.IPAddress((uint)i);
                case uint u: return new System.Net.IPAddress(u);
                case long l: return new System.Net.IPAddress((uint)l);
                case byte[] { Length: 4 or 16 } b: return new System.Net.IPAddress(b);
            }
            string s = v.ToString() ?? "";
            if (int.TryParse(s, out int n)) return new System.Net.IPAddress((uint)n);
            return System.Net.IPAddress.TryParse(s, out var p) ? p : null;
        }
        catch { return null; }
    }

    private string? StartOwnSession()
    {
        try
        {
            try { TraceEventSession.GetActiveSession(OwnSessionName)?.Stop(true); } catch { }
            _session = new TraceEventSession(OwnSessionName) { StopOnDispose = true };
            _session.EnableProvider(KernelNetwork, TraceEventLevel.Informational, 0x30 /* IPv4 + IPv6 */);
            var parser = new RegisteredTraceEventParser(_session.Source);
            parser.All += e =>
            {
                int id = (int)e.ID;
                bool send = SendIds.Contains(id);
                if (!send && !RecvIds.Contains(id)) return;
                try
                {
                    int pid = Convert.ToInt32(e.PayloadByName("PID") ?? e.ProcessID);
                    int size = Convert.ToInt32(e.PayloadByName("size") ?? 0);
                    var ip = EtwAddress(e.PayloadByName("daddr")) ?? System.Net.IPAddress.None;
                    Add(pid, size, ip, incoming: !send);
                }
                catch { }
            };
            Run();
            return null;
        }
        catch (Exception ex)
        {
            try { _session?.Dispose(); } catch { }
            _session = null;
            return ex.Message;
        }
    }

    private string? StartKernelSession()
    {
        try
        {
            _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName) { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            var kernel = _session.Source.Kernel;
            kernel.TcpIpRecv += e => Add(e.ProcessID, e.size, e.daddr, incoming: true);
            kernel.TcpIpRecvIPV6 += e => Add(e.ProcessID, e.size, e.daddr, incoming: true);
            kernel.UdpIpRecv += e => Add(e.ProcessID, e.size, e.daddr, incoming: true);
            kernel.UdpIpRecvIPV6 += e => Add(e.ProcessID, e.size, e.daddr, incoming: true);
            kernel.TcpIpSend += e => Add(e.ProcessID, e.size, e.daddr, incoming: false);
            kernel.TcpIpSendIPV6 += e => Add(e.ProcessID, e.size, e.daddr, incoming: false);
            kernel.UdpIpSend += e => Add(e.ProcessID, e.size, e.daddr, incoming: false);
            kernel.UdpIpSendIPV6 += e => Add(e.ProcessID, e.size, e.daddr, incoming: false);
            Run();
            return null;
        }
        catch (Exception ex)
        {
            try { _session?.Dispose(); } catch { }
            _session = null;
            return ex.Message;
        }
    }

    private void Run()
    {
        var session = _session!;
        IsRunning = true;
        _task = Task.Run(() =>
        {
            try { session.Source.Process(); }
            catch (Exception ex) { Error?.Invoke("El monitor de tráfico se ha detenido: " + ex.Message); }
            finally { if (_session == session) IsRunning = false; }
        });
    }

    private void Add(int pid, int size, System.Net.IPAddress remote, bool incoming)
    {
        // El tráfico interno del propio equipo (localhost) no sale a la red: se ignora.
        if (size <= 0 || System.Net.IPAddress.IsLoopback(remote)) return;
        lock (_lock)
        {
            if (!_perProcess.TryGetValue(pid, out var t))
                _perProcess[pid] = t = new ProcessTraffic();
            if (incoming) t.BytesIn += size; else t.BytesOut += size;
        }
        if (incoming) Interlocked.Add(ref _totalIn, size);
        else Interlocked.Add(ref _totalOut, size);
    }

    /// <summary>Copia de los contadores acumulados por PID desde que arrancó el monitor.</summary>
    public Dictionary<int, (long In, long Out)> Snapshot()
    {
        lock (_lock)
        {
            var copy = new Dictionary<int, (long, long)>(_perProcess.Count);
            foreach (var kv in _perProcess) copy[kv.Key] = (kv.Value.BytesIn, kv.Value.BytesOut);
            return copy;
        }
    }

    /// <summary>Olvida los contadores de procesos que ya no existen.</summary>
    public void Forget(IEnumerable<int> deadPids)
    {
        lock (_lock)
        {
            foreach (var pid in deadPids) _perProcess.Remove(pid);
        }
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
