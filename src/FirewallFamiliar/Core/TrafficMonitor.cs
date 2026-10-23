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

    public void Start()
    {
        if (!(TraceEventSession.IsElevated() ?? false))
        {
            Error?.Invoke("Hace falta ejecutar como administrador para ver el tráfico por programa.");
            return;
        }

        try
        {
            // Windows solo permite una sesión del "NT Kernel Logger" a la vez.
            // Si quedó una abierta (por ejemplo, de un cierre anterior), se reemplaza.
            _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName)
            {
                StopOnDispose = true
            };
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

            IsRunning = true;
            _task = Task.Run(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) { Error?.Invoke("El monitor de tráfico se ha detenido: " + ex.Message); }
                finally { IsRunning = false; }
            });
        }
        catch (Exception ex)
        {
            IsRunning = false;
            Error?.Invoke("No se pudo iniciar el monitor de tráfico: " + ex.Message);
        }
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
