using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallFamiliar.Core;

/// <summary>Foto de un programa en ejecución para el informe.</summary>
public sealed record ProcessSummary(string Name, int Pid, string Path, string Kind, string Level, string Signature,
    string Rule, long Memory, int Connections, int Listening, long BytesIn, long BytesOut, string Suspicious);

/// <summary>
/// Prepara un informe en un solo archivo de texto (Markdown) con todo lo necesario para que
/// otra persona, o Claude, pueda auditar el equipo: avisos, resúmenes por programa y por IP
/// (con su dueño), actividad por horas, reglas y el registro de seguridad completo.
/// El tráfico va resumido para que el archivo no sea enorme.
/// </summary>
public static class AnalysisReport
{
    private const int MaxSecurityLines = 4000;
    private const int MaxOwnerLookups = 80;

    public static Task<string> BuildAsync(int days, RuleSet rules, IReadOnlyList<ProcessSummary> processes,
        IProgress<string>? progress = null, CancellationToken cancel = default) =>
        BuildAsync(DateTime.Today.AddDays(-(days - 1)), DateTime.Today, rules, processes, progress, cancel);

    /// <summary>Informe de los días entre <paramref name="from"/> y <paramref name="to"/> (los dos incluidos).</summary>
    public static async Task<string> BuildAsync(DateTime from, DateTime to, RuleSet rules, IReadOnlyList<ProcessSummary> processes,
        IProgress<string>? progress = null, CancellationToken cancel = default)
    {
        from = from.Date;
        to = to.Date;
        int days = (int)(to - from).TotalDays + 1;
        progress?.Report("Leyendo registros...");
        var (security, traffic) = await Task.Run(() =>
        {
            var s = new List<LogEntry>();
            var t = new List<LogEntry>();
            for (var d = from; d <= to; d = d.AddDays(1))
            {
                s.AddRange(LogStore.Read(LogKind.Seguridad, d));
                t.AddRange(LogStore.Read(LogKind.Trafico, d));
            }
            return (s, t);
        }, cancel);

        // Dueños de las IP públicas más vistas
        var topIps = traffic.Concat(security)
            .Where(e => e.Remote != null && IPAddress.TryParse(e.Remote, out var ip) && IpInfo.Special(ip) == null)
            .GroupBy(e => e.Remote!).OrderByDescending(g => g.Count()).Take(MaxOwnerLookups).Select(g => g.Key).ToList();
        var owners = new Dictionary<string, IpOwner>();
        int n = 0;
        foreach (var batch in topIps.Chunk(4))
        {
            cancel.ThrowIfCancellationRequested();
            progress?.Report($"Buscando a quién pertenecen las IP ({n}/{topIps.Count})...");
            var results = await Task.WhenAll(batch.Select(async ip =>
            {
                try
                {
                    var lookup = IpInfo.LookupAsync(IPAddress.Parse(ip));
                    var done = await Task.WhenAny(lookup, Task.Delay(30000, cancel));
                    return (ip, done == lookup ? lookup.Result : null);
                }
                catch { return (ip, (IpOwner?)null); }
            }));
            foreach (var (ip, owner) in results) if (owner != null) owners[ip] = owner;
            n += batch.Length;
        }

        progress?.Report("Escribiendo el informe...");
        return await Task.Run(() => Write(days, from, to, rules, processes, security, traffic, owners), cancel);
    }

    private static string Write(int days, DateTime from, DateTime to, RuleSet rules, IReadOnlyList<ProcessSummary> procs,
        List<LogEntry> security, List<LogEntry> traffic, Dictionary<string, IpOwner> owners)
    {
        var sb = new StringBuilder();
        string Owner(string? ip)
        {
            if (ip == null) return "";
            if (IPAddress.TryParse(ip, out var a) && IpInfo.Special(a) is { } special) return special;
            if (!owners.TryGetValue(ip, out var o) || o.Note.StartsWith("No se pudo")) return "";
            return o.Note.Length > 0 ? o.Note : o.Country.Length > 0 ? $"{o.Organization} ({o.Country})" : o.Organization;
        }
        static string Cell(string? s) => (s ?? "").Replace("|", "/").Replace("\n", " ").Trim();

        // ---------------- Cabecera ----------------
        sb.AppendLine("# Informe de Firewall Familiar para análisis");
        sb.AppendLine();
        sb.AppendLine("Este archivo lo genera Firewall Familiar para que una persona o una IA (Claude) revise la actividad de red de este ordenador.");
        sb.AppendLine("Busca: programas desconocidos o sospechosos, conexiones a sitios raros, intentos de entrada, uso a horas extrañas y reglas mejorables.");
        sb.AppendLine();
        sb.AppendLine($"- Equipo: {Environment.MachineName}   Usuario: {(Environment.UserName.EndsWith("$") || Environment.UserName == "SYSTEM" ? "(informe automático del servicio)" : Environment.UserName)}");
        sb.AppendLine($"- Windows: {Environment.OSVersion.VersionString}");
        sb.AppendLine($"- Firewall Familiar: {typeof(AnalysisReport).Assembly.GetName().Version?.ToString(3)}");
        sb.AppendLine($"- Periodo: {from:dd/MM/yyyy} a {to:dd/MM/yyyy} ({days} día{(days == 1 ? "" : "s")})   Generado: {DateTime.Now:dd/MM/yyyy HH:mm}");
        sb.AppendLine($"- Modo de seguridad: {rules.Mode}   Permitir componentes de Windows solos: {(rules.AllowWindowsComponents ? "sí" : "no")}");
        sb.AppendLine($"- Eventos de seguridad: {security.Count}   Eventos de tráfico: {traffic.Count}");
        sb.AppendLine("- Nota: el registro de tráfico anota cada conexión TCP nueva y cada intento bloqueado (los repetidos en 10 s se juntan). No guarda el contenido.");
        sb.AppendLine();

        // ---------------- Avisos ----------------
        var alerts = security.Where(e => e.Outcome is "Escaneo" or "Sospechoso" or "Oculto" or "AccesoRemoto" or "Alerta").ToList();
        sb.AppendLine($"## 1. Avisos importantes ({alerts.Count})");
        sb.AppendLine();
        if (alerts.Count == 0) sb.AppendLine("Ninguno.");
        foreach (var a in alerts.Take(500))
            sb.AppendLine($"- {a.Time:dd/MM HH:mm:ss} [{a.Outcome}] {Cell(a.Text)}{(a.App != null ? $"  · Ruta: {a.App}" : "")}{(a.Remote != null ? $"  · IP: {a.Remote} {Owner(a.Remote)}" : "")}");
        sb.AppendLine();

        // ---------------- Programas ahora ----------------
        var interesting = procs.Where(p => p.Level != "Normal" || p.Connections > 0 || p.Listening > 0 || p.BytesIn + p.BytesOut > 0)
            .OrderBy(p => p.Level switch { "⚠ Crítico" => 0, "Medio" => 1, _ => 2 }).ThenBy(p => p.Name).ToList();
        sb.AppendLine($"## 2. Programas en ejecución ahora que usan la red o son de riesgo ({interesting.Count} de {procs.Count})");
        sb.AppendLine();
        sb.AppendLine("| Nivel | Programa | PID | Tipo | Firma | Regla | Memoria | Conex. | Escucha | Recibido | Enviado | Ruta | Motivo |");
        sb.AppendLine("|---|---|---|---|---|---|---|---|---|---|---|---|---|");
        foreach (var p in interesting)
            sb.AppendLine($"| {p.Level} | {Cell(p.Name)} | {p.Pid} | {p.Kind} | {Cell(p.Signature)} | {Cell(p.Rule)} | {Mb(p.Memory)} | {p.Connections} | {p.Listening} | {Mb(p.BytesIn)} | {Mb(p.BytesOut)} | {Cell(p.Path)} | {Cell(p.Suspicious)} |");
        sb.AppendLine();

        // ---------------- Por programa ----------------
        var byApp = traffic.GroupBy(e => e.App ?? "").OrderByDescending(g => g.Count()).ToList();
        sb.AppendLine($"## 3. Resumen del tráfico por programa ({byApp.Count})");
        sb.AppendLine();
        sb.AppendLine("| Programa | Conexiones | Bloqueos | IP distintas | Primera | Última | Destinos principales (IP:puerto, dueño, veces) |");
        sb.AppendLine("|---|---|---|---|---|---|---|");
        foreach (var g in byApp)
        {
            var top = g.Where(e => e.Remote != null).GroupBy(e => (e.Remote, Port: e.Inbound ? e.LocalPort : e.RemotePort))
                .OrderByDescending(x => x.Count()).Take(6)
                .Select(x => $"{x.Key.Remote}:{x.Key.Port} {Owner(x.Key.Remote)} ×{x.Count()}");
            sb.AppendLine($"| {(g.Key.Length == 0 ? "(sin programa: Windows o servicio del sistema)" : Cell(Path.GetFileName(g.Key)))} | {g.Count(e => e.Outcome == "Permitido")} | {g.Count(e => e.Outcome == "Bloqueado")} | " +
                          $"{g.Select(e => e.Remote).Distinct().Count()} | {g.Min(e => e.Time):dd/MM HH:mm} | {g.Max(e => e.Time):dd/MM HH:mm} | {Cell(string.Join("; ", top))} |");
        }
        sb.AppendLine();

        // ---------------- Por IP ----------------
        var byIp = traffic.Where(e => e.Remote != null).GroupBy(e => e.Remote!).OrderByDescending(g => g.Count()).Take(300).ToList();
        sb.AppendLine($"## 4. Direcciones IP más contactadas (las {byIp.Count} primeras)");
        sb.AppendLine();
        sb.AppendLine("| IP | Pertenece a | Veces | Bloqueos | Programas | Puertos (para qué) |");
        sb.AppendLine("|---|---|---|---|---|---|");
        foreach (var g in byIp)
        {
            var apps = g.Select(e => e.AppName).Where(a => a.Length > 0).Distinct().Take(5);
            var ports = g.Select(e => e.Inbound ? e.LocalPort : e.RemotePort).Distinct().Take(6)
                .Select(p => { string m = Ports.Describe(p, "TCP"); return m.Length > 0 ? $"{p} ({m})" : p.ToString(); });
            sb.AppendLine($"| {g.Key} | {Cell(Owner(g.Key))} | {g.Count()} | {g.Count(e => e.Outcome == "Bloqueado")} | {Cell(string.Join(", ", apps))} | {Cell(string.Join(", ", ports))} |");
        }
        sb.AppendLine();

        // ---------------- Entradas desde fuera ----------------
        // Respuestas que llegan tarde (de un servidor con el que este PC ya hablaba) no son intentos de entrar
        var contacted = traffic.Where(e => !e.Inbound && e.Remote != null).Select(e => e.Remote!).ToHashSet();
        bool IsLateReply(LogEntry e) =>
            e.LocalPort >= 1024 && (ScanDetector.LooksLikeReply(e.RemotePort, e.LocalPort) || contacted.Contains(e.Remote!));
        var allInbound = traffic.Where(e => e.Inbound && e.Outcome == "Bloqueado" && e.Remote != null).ToList();
        var replies = allInbound.Where(IsLateReply).ToList();
        var inbound = allInbound.Where(e => !IsLateReply(e))
            .GroupBy(e => e.Remote!).OrderByDescending(g => g.Count()).Take(100).ToList();
        sb.AppendLine($"## 5. Intentos de entrada bloqueados, por origen ({inbound.Count})");
        sb.AppendLine();
        if (replies.Count > 0)
            sb.AppendLine($"- Aparte, {replies.Count} respuestas tardías de {replies.Select(e => e.Remote).Distinct().Count()} servidores con los que este PC ya hablaba " +
                          "(webs, DNS, VPN...). Se bloquean porque llegan cuando la conexión ya se había cerrado; no son ataques y no se listan.");
        if (inbound.Count == 0) sb.AppendLine("Ningún otro intento registrado.");
        else
        {
            sb.AppendLine("| Origen | Pertenece a | Intentos | Puertos locales probados | Primero | Último |");
            sb.AppendLine("|---|---|---|---|---|---|");
            foreach (var g in inbound)
                sb.AppendLine($"| {g.Key} | {Cell(Owner(g.Key))} | {g.Count()} | {string.Join(", ", g.Select(e => e.LocalPort).Distinct().OrderBy(p => p).Take(20))} | {g.Min(e => e.Time):dd/MM HH:mm} | {g.Max(e => e.Time):dd/MM HH:mm} |");
        }
        sb.AppendLine();

        // ---------------- Por horas ----------------
        sb.AppendLine("## 6. Actividad por hora del día (conexiones nuevas, todos los días juntos)");
        sb.AppendLine();
        var hours = traffic.Where(e => e.Outcome == "Permitido").GroupBy(e => e.Time.Hour).ToDictionary(g => g.Key, g => g.Count());
        int max = Math.Max(1, hours.Values.DefaultIfEmpty(0).Max());
        sb.AppendLine("```");
        for (int h = 0; h < 24; h++)
        {
            int c = hours.GetValueOrDefault(h);
            sb.AppendLine($"{h:00}:00 {new string('#', (int)Math.Ceiling(40.0 * c / max)),-40} {c}");
        }
        sb.AppendLine("```");
        sb.AppendLine();
        var perDay = traffic.GroupBy(e => e.Time.Date).OrderBy(g => g.Key)
            .Select(g => $"- {g.Key:ddd dd/MM}: {g.Count(e => e.Outcome == "Permitido")} conexiones, {g.Count(e => e.Outcome == "Bloqueado")} bloqueos, de {g.Min(e => e.Time):HH:mm} a {g.Max(e => e.Time):HH:mm}");
        foreach (var line in perDay) sb.AppendLine(line);
        sb.AppendLine();

        // ---------------- Reglas ----------------
        sb.AppendLine($"## 7. Reglas actuales ({rules.Apps.Count} de programas, {rules.Advanced.Count} avanzadas)");
        sb.AppendLine();
        foreach (var r in rules.Apps.OrderBy(a => a.Action).ThenBy(a => a.Name))
            sb.AppendLine($"- {r.Action}: {r.Path}  (desde {r.Created:dd/MM/yyyy})");
        foreach (var r in rules.Advanced)
            sb.AppendLine($"- Avanzada{(r.Enabled ? "" : " (desactivada)")}: {Cell(r.Name)} → {Cell(r.Summary)}");
        sb.AppendLine();

        // ---------------- Registro de seguridad ----------------
        var sec = security.Count > MaxSecurityLines ? security.Skip(security.Count - MaxSecurityLines).ToList() : security;
        sb.AppendLine($"## 8. Registro de seguridad completo{(security.Count > MaxSecurityLines ? $" (últimas {MaxSecurityLines} líneas de {security.Count})" : "")}");
        sb.AppendLine();
        sb.AppendLine("```");
        foreach (var e in sec)
            sb.AppendLine($"{e.Time:dd/MM HH:mm:ss} {(e.Outcome.Length > 0 ? $"[{e.Outcome}] " : "")}{e.Text}{(e.App != null && !e.Text.Contains(e.App) ? $" <{e.App}>" : "")}");
        sb.AppendLine("```");
        return sb.ToString();
    }

    private static string Mb(long bytes) => bytes == 0 ? "0" : (bytes / 1024.0 / 1024).ToString("0.0", CultureInfo.InvariantCulture) + " MB";
}
