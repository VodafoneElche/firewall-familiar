using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace FirewallFamiliar.Service;

/// <summary>
/// Mira los nombres que el PC pregunta al DNS (con los eventos del cliente DNS de Windows) y avisa
/// cuando alguno es de un servidor de programa espía conocido. Las IPs que devuelve se bloquean,
/// porque esos servidores cambian de IP mucho más a menudo que de nombre.
/// </summary>
internal sealed class DnsWatcher : IDisposable
{
    private const string SessionName = "FirewallFamiliar-DNS";
    private static readonly Guid DnsClient = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private const int QueryCompleted = 3008;

    /// <summary>nombre consultado, IPs de la respuesta, PID que preguntó.</summary>
    private readonly Action<string, List<IPAddress>, int> _onQuery;
    private TraceEventSession? _session;

    public DnsWatcher(Action<string, List<IPAddress>, int> onQuery) => _onQuery = onQuery;

    public string? Start()
    {
        try
        {
            try { TraceEventSession.GetActiveSession(SessionName)?.Stop(true); } catch { }
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session.EnableProvider(DnsClient, TraceEventLevel.Informational);
            var parser = new RegisteredTraceEventParser(_session.Source);
            parser.All += OnEvent;
            Task.Run(() => { try { _session.Source.Process(); } catch { } });
            return null;
        }
        catch (Exception ex) { return ex.Message; }
    }

    private void OnEvent(TraceEvent e)
    {
        if ((int)e.ID != QueryCompleted) return;
        try
        {
            string name = e.PayloadByName("QueryName")?.ToString() ?? "";
            if (name.Length == 0) return;
            _onQuery(name, ParseResults(e.PayloadByName("QueryResults")?.ToString() ?? ""), e.ProcessID);
        }
        catch { }
    }

    /// <summary>"type:  5 alias.example;::ffff:1.2.3.4;2001:db8::1;" → las IPs.</summary>
    internal static List<IPAddress> ParseResults(string results)
    {
        var list = new List<IPAddress>();
        foreach (var part in results.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string p = part.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) ? part[7..] : part;
            if (IPAddress.TryParse(p, out var ip)) list.Add(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip);
        }
        return list;
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
