using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Service;

/// <summary>
/// Vigilante del router (cada 15 minutos, sin salir de casa):
///  - aparato nuevo en la red de casa → aviso urgente (correo del SOC); fuera de casa no se avisa
///    de aparatos, solo de lo crítico para este PC (UPnP hacia él, Telnet abierto en el router);
///  - puerto nuevo abierto por UPnP hacia este PC con un programa sin firma, o hacia cualquier
///    aparato en un puerto de control remoto → urgente; los demás se apuntan en el registro;
///  - cada 6 horas mira las puertas del router y avisa si se abre una peligrosa (Telnet, SSH...).
/// Cada red se recuerda por la MAC de su router: un portátil fuera de casa aprende la red nueva
/// en silencio la primera vez, sin avisar de todo lo que ve.
/// </summary>
internal sealed class RouterWatch
{
    private static readonly string StateFile = Path.Combine(RuleStore.Folder, "router.json");
    private static readonly int[] RemotePorts = { 21, 22, 23, 139, 445, 3389, 5900, 5938, 7070 };

    private readonly Action<string, string, string?> _log;
    private readonly Dictionary<string, Net> _nets;
    private int _busy;
    private DateTime _lastPorts = DateTime.MinValue;

    private sealed class Net
    {
        public HashSet<string> Devices { get; set; } = new();
        public HashSet<string> Mappings { get; set; } = new();
        public HashSet<int> OpenPorts { get; set; } = new();
        public bool PortsKnown { get; set; }
        /// <summary>Ya se ha hecho una vez el barrido de toda la red (lo que salga la primera vez se aprende sin avisar).</summary>
        public bool Swept { get; set; }
        public bool? Upnp { get; set; }
        public DateTime FirstSeen { get; set; } = DateTime.Now;
    }

    public RouterWatch(Action<string, string, string?> log)
    {
        _log = log;
        _nets = Load();
    }

    public void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            bool ports = DateTime.Now - _lastPorts > TimeSpan.FromHours(6);
            // En casa se pregunta antes por ARP a toda la red: así salen también los aparatos que
            // no han hablado con este PC (móviles, teles, visitas...), no solo los de la tabla ARP.
            bool swept = false;
            var (gw0, key0) = RouterCheck.CurrentNetwork();
            string? home0 = RouterCheck.HomeNetwork();
            if (gw0.Length > 0 && key0.Length > 0 && (home0 == null || RouterCheck.SameNet(home0, key0)))
            {
                NetScan.Sweep(gw0);
                swept = true;
            }
            var r = RouterCheck.Run(ports);
            if (ports && r.Ports.Count > 0) _lastPorts = DateTime.Now;
            if (r.Gateway.Length == 0 || r.GatewayMac.Length == 0) return;

            // Estado guardado con la clave antigua (solo MAC, hasta la 0.14.2): se pasa a la nueva
            if (!_nets.ContainsKey(r.NetworkKey) && _nets.Remove(r.GatewayMac, out var oldNet)) _nets[r.NetworkKey] = oldNet;
            bool first = !_nets.TryGetValue(r.NetworkKey, out var net);
            net ??= _nets[r.NetworkKey] = new Net();
            string where = $"red del router {r.Gateway}";
            // La primera red que ve el servicio es la de casa (se cambia en la ventana Router).
            // Fuera de casa (oficina, casa de amigos...) solo se avisa de lo crítico para este PC.
            string? homeKey = RouterCheck.HomeNetwork();
            if (homeKey == null) { RouterCheck.SetHomeNetwork(r.NetworkKey); homeKey = r.NetworkKey; }
            bool home = RouterCheck.IsHomeNetwork(r.NetworkKey) == true;

            // Aparatos (el primer barrido de toda la red tras actualizar se aprende en silencio)
            bool learn = first || (swept && home && !net.Swept);
            var book = DeviceBook.Load();
            foreach (var d in r.Devices.Where(d => !d.IsThisPc))
            {
                if (!net.Devices.Add(d.Mac) || learn || !home) continue;
                if (book.TryGetValue(d.Mac, out var known) && known.Home) continue; // ya le has puesto nombre como de casa
                var q = NetScan.Quick(d.Ip, d.Mac, r.Gateway);
                var what = new List<string> { d.VendorText };
                if (q.HostName.Length > 0) what.Insert(0, $"se llama \"{q.HostName}\"");
                if (q.TypeText.Length > 0) what.Add("parece: " + q.TypeText.ToLowerInvariant());
                else if (d.Kind.Length > 0) what.Add(d.Kind.ToLowerInvariant());
                var danger = q.OpenPorts.Where(p => NetScan.PortLevel(p) >= 3).Select(p => $"{p} {NetScan.PortName(p)}").ToList();
                _log($"⚠ APARATO NUEVO EN LA RED DE CASA: {d.Ip} (MAC {d.Mac}, {string.Join(", ", what)})" +
                     (danger.Count > 0 ? $". Tiene abierta: {string.Join(", ", danger)}" : "") + ". " +
                     "Si no sabes qué es (visita, móvil nuevo, tele...), cambia la contraseña del Wi-Fi. " +
                     "Si es de casa, ponle nombre en Router > Aparatos de la red.", "Alerta", null);
            }
            if (swept && home) net.Swept = true;

            // UPnP
            if (r.UpnpOn != null && net.Upnp != r.UpnpOn)
            {
                if (!first && net.Upnp != null && home)
                    _log(r.UpnpOn == true ? $"Router: UPnP se ha encendido en la {where}. {r.UpnpNote}" : $"Router: UPnP ya no contesta en la {where}.", "", null);
                net.Upnp = r.UpnpOn;
            }
            var now = r.Mappings.Select(m => m.Key).ToHashSet();
            foreach (var m in r.Mappings)
            {
                if (!net.Mappings.Add(m.Key) || first) continue;
                bool toMe = m.InternalClient == r.LocalIp;
                if (!home && !toMe) continue; // fuera de casa, los aparatos de otros no son cosa nuestra
                bool remote = RemotePorts.Contains(m.InternalPort);
                bool unsigned = toMe && m.Program.Length > 0 && File.Exists(m.Program) &&
                                Signature.CheckNow(m.Program).Status != SignatureStatus.Valida && !Signature.IsOwn(m.Program);
                if (remote || unsigned || (toMe && m.Program.Length == 0))
                    _log($"⚠ PUERTO ABIERTO EN EL ROUTER: {m.Text}. Desde Internet se puede entrar ahí. " +
                         "Si no sabes qué programa es, ciérralo o apaga UPnP en el router.", "Alerta", toMe && m.Program.Length > 0 ? m.Program : null);
                else
                    _log($"Router: un programa ha abierto un puerto por UPnP: {m.Text}.", "", toMe && m.Program.Length > 0 ? m.Program : null);
            }
            // Los que se cierran se olvidan (si vuelven, se avisa otra vez); si el router no ha
            // contestado esta vez, no se olvida nada para no repetir avisos
            if (r.UpnpOn == false || r.Mappings.Count > 0) net.Mappings.IntersectWith(now);

            // Puertas del router
            if (r.Ports.Count > 0 && !r.RouterSilent)
            {
                var open = r.Ports.Where(p => p.Open).ToList();
                foreach (var p in open)
                {
                    if (net.OpenPorts.Contains(p.Port) || !net.PortsKnown || first) continue;
                    if (p.Level >= (home ? 2 : 3))
                        _log($"⚠ PUERTA NUEVA EN EL ROUTER: {p.Port} {p.Service} contesta desde hoy. {p.Advice}", "Alerta", null);
                    else if (home)
                        _log($"Router: ahora contesta el puerto {p.Port} {p.Service}.", "", null);
                }
                net.OpenPorts = open.Select(p => p.Port).ToHashSet();
                net.PortsKnown = true;
            }
            Save();
        }
        catch { }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    private static Dictionary<string, Net> Load()
    {
        try
        {
            if (File.Exists(StateFile))
                return JsonSerializer.Deserialize<Dictionary<string, Net>>(File.ReadAllText(StateFile)) ?? new();
        }
        catch { }
        return new();
    }

    private void Save()
    {
        try
        {
            string tmp = StateFile + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_nets));
            File.Move(tmp, StateFile, true);
        }
        catch { }
    }
}
