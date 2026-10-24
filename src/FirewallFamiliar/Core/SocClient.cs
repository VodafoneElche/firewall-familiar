using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallFamiliar.Core;

/// <summary>
/// SOC familiar: manda informes, avisos y "latidos" al buzón del Google Drive de la familia.
/// El buzón es un pequeño programa (Google Apps Script) en la cuenta del SOC; los PCs solo
/// conocen su dirección y una clave, nunca la contraseña de la cuenta de Google.
/// </summary>
public static class SocClient
{
    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        // Google contesta con una redirección: hay que seguirla para leer la respuesta
        var h = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 };
        var c = new HttpClient(h) { Timeout = Timeout.InfiniteTimeSpan };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("FirewallFamiliar/" + Updater.Current.ToString(3));
        return c;
    }

    /// <summary>
    /// Envía un mensaje al buzón. <paramref name="type"/>: "latido", "adios", "aviso" o "informe".
    /// Devuelve null si ha llegado bien, o el motivo del fallo.
    /// </summary>
    public static async Task<string?> SendAsync(AppSettings s, string type, object data, int timeoutSeconds = 60)
    {
        if (!s.SocEnabled) return "El SOC familiar no está configurado.";
        var body = new System.Collections.Generic.Dictionary<string, object?>
        {
            ["tipo"] = type,
            ["equipo"] = s.SocComputer,
            ["version"] = Updater.Current.ToString(3),
            ["hora"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            ["datos"] = data
        };
        string url = s.SocUrl.Trim();
        url += (url.Contains('?') ? "&" : "?") + "k=" + Uri.EscapeDataString(s.SocKey.Trim());
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            using var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "text/plain");
            using var resp = await Http.PostAsync(url, content, cts.Token);
            string text = (await resp.Content.ReadAsStringAsync(cts.Token)).Trim();
            if (text == "ok") return null;
            if (text == "no") return "El buzón no acepta la clave. Revisa que sea la misma que SECRETO en el script.";
            if (!resp.IsSuccessStatusCode) return $"El buzón contestó con un error ({(int)resp.StatusCode}).";
            return text.Length > 0 && text.Length < 200 && !text.Contains('<')
                ? "Respuesta inesperada del buzón: " + text
                : "El buzón no contestó lo esperado. ¿La dirección es la de la aplicación web publicada (termina en /exec)?";
        }
        catch (OperationCanceledException) { return "El buzón no contesta (tiempo agotado)."; }
        catch (HttpRequestException ex) { return "No se puede llegar al buzón: " + ex.Message; }
        catch (Exception ex) { return ex.Message; }
    }
}
