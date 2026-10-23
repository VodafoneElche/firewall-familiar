using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;

namespace FirewallFamiliar.Core;

/// <summary>A quién pertenece una dirección IP.</summary>
public sealed record IpOwner(string Organization, string Network, string Country, string Note);

/// <summary>
/// Averigua el dueño de una IP con el servicio público RDAP (el "registro de la propiedad"
/// de las direcciones de Internet: RIPE, ARIN...). No necesita clave ni cuenta.
/// </summary>
public static class IpInfo
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private static readonly ConcurrentDictionary<string, Task<IpOwner>> Cache = new();

    static IpInfo()
    {
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("FirewallFamiliar/1.0");
        Http.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json, application/json");
    }

    /// <summary>Explica direcciones especiales sin consultar Internet, o devuelve null.</summary>
    public static string? Special(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return "Este mismo ordenador";
        byte[] b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168))
                return "Red de casa (router, otro ordenador, móvil, impresora...)";
            if (b[0] == 169 && b[1] == 254) return "Red local sin configurar";
            if (b[0] >= 224 && b[0] <= 239) return "Mensaje para varios aparatos de la red de casa (multidifusión)";
            if (b.All(x => x == 255)) return "Mensaje para todos los aparatos de la red de casa";
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return "Red interna del proveedor de Internet";
        }
        else
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC) return "Red de casa (IPv6)";
            if (ip.IsIPv6Multicast) return "Mensaje para varios aparatos de la red de casa (multidifusión)";
        }
        return null;
    }

    public static Task<IpOwner> LookupAsync(IPAddress ip)
    {
        var special = Special(ip);
        if (special != null) return Task.FromResult(new IpOwner(special, "", "", ""));
        return Cache.GetOrAdd(ip.ToString(), _ => QueryAsync(ip));
    }

    private static async Task<IpOwner> QueryAsync(IPAddress ip)
    {
        try
        {
            using var doc = JsonDocument.Parse(await Http.GetStringAsync("https://rdap.org/ip/" + ip));
            var root = doc.RootElement;
            string network = Str(root, "name");
            string country = Str(root, "country");
            string org = "";
            if (root.TryGetProperty("entities", out var entities))
                org = FindOrganization(entities, "registrant") ?? FindOrganization(entities, null) ?? "";
            if (org.Length == 0) org = network;
            return new IpOwner(org, network, CountryName(country), "");
        }
        catch (Exception ex)
        {
            Cache.TryRemove(ip.ToString(), out _); // reintentar la próxima vez
            return new IpOwner("", "", "", "No se pudo consultar el dueño: " + ex.Message);
        }
    }

    /// <summary>Busca el nombre ("fn") de la primera entidad con ese papel, también en entidades anidadas.</summary>
    private static string? FindOrganization(JsonElement entities, string? role)
    {
        if (entities.ValueKind != JsonValueKind.Array) return null;
        foreach (var e in entities.EnumerateArray())
        {
            bool roleOk = role == null ||
                (e.TryGetProperty("roles", out var roles) && roles.EnumerateArray().Any(r => r.GetString() == role));
            if (roleOk && e.TryGetProperty("vcardArray", out var vcard) && vcard.GetArrayLength() > 1)
            {
                foreach (var field in vcard[1].EnumerateArray())
                {
                    if (field.GetArrayLength() >= 4 && field[0].GetString() == "fn")
                    {
                        string fn = field[3].ToString();
                        if (fn.Length > 0) return fn;
                    }
                }
            }
            if (e.TryGetProperty("entities", out var nested))
            {
                var found = FindOrganization(nested, role);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static string CountryName(string code)
    {
        if (code.Length != 2) return code;
        try { return new System.Globalization.RegionInfo(code).DisplayName; }
        catch { return code; }
    }
}
