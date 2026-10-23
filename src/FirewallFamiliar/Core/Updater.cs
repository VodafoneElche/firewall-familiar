using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace FirewallFamiliar.Core;

/// <summary>Una versión nueva publicada en GitHub.</summary>
public sealed record UpdateInfo(Version Version, string Tag, string InstallerUrl, string? Sha256Url, string Notes);

/// <summary>
/// Actualización automática: mira en las "Releases" del repositorio público de versiones si hay
/// una versión más nueva, descarga el instalador y lo ejecuta en silencio. Como lo descarga el
/// propio programa (y no el navegador), Windows no lo marca como "descargado de Internet".
/// </summary>
public static class Updater
{
    public const string Repository = "VodafoneElche/firewall-familiar-versiones";
    private const string InstallerName = "FirewallFamiliar-Instalar.exe";

    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("FirewallFamiliar/" + Current.ToString(3));
        c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return c;
    }

    public static Version Current => typeof(Updater).Assembly.GetName().Version ?? new Version(0, 0, 0);

    /// <summary>Devuelve la versión nueva si la hay, o null si ya está al día.</summary>
    public static async Task<UpdateInfo?> CheckAsync()
    {
        string json = await Http.GetStringAsync($"https://api.github.com/repos/{Repository}/releases/latest");
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!Version.TryParse(tag.TrimStart('v', 'V'), out var version)) return null;
        if (Normalize(version) <= Normalize(Current)) return null;

        string? installer = null, sha = null;
        foreach (var asset in root.GetProperty("assets").EnumerateArray())
        {
            string name = asset.GetProperty("name").GetString() ?? "";
            string url = asset.GetProperty("browser_download_url").GetString() ?? "";
            if (name.Equals(InstallerName, StringComparison.OrdinalIgnoreCase)) installer = url;
            else if (name.Equals(InstallerName + ".sha256", StringComparison.OrdinalIgnoreCase)) sha = url;
        }
        if (installer == null) return null;
        string notes = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
        return new UpdateInfo(version, tag, installer, sha, notes);
    }

    private static Version Normalize(Version v) => new(v.Major, v.Minor, Math.Max(0, v.Build));

    /// <summary>Descarga el instalador a C:\ProgramData\FirewallFamiliar\actualizacion y comprueba que llegó entero.</summary>
    public static async Task<string> DownloadAsync(UpdateInfo info)
    {
        string dir = Path.Combine(RuleStore.Folder, "actualizacion");
        Directory.CreateDirectory(dir);
        foreach (var old in Directory.EnumerateFiles(dir)) { try { File.Delete(old); } catch { } }
        string file = Path.Combine(dir, $"FirewallFamiliar-Instalar-{info.Version.ToString(3)}.exe");

        await using (var src = await Http.GetStreamAsync(info.InstallerUrl))
        await using (var dst = File.Create(file))
            await src.CopyToAsync(dst);

        if (info.Sha256Url != null)
        {
            string expected = (await Http.GetStringAsync(info.Sha256Url)).Trim().Split(' ', '\t')[0];
            await using var fs = File.OpenRead(file);
            string actual = Convert.ToHexString(await SHA256.HashDataAsync(fs));
            if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(file);
                throw new InvalidOperationException("la descarga ha llegado dañada");
            }
        }
        return file;
    }

    /// <summary>Lanza el instalador en silencio. Él cierra este programa y lo vuelve a abrir junto al reloj.</summary>
    public static void RunInstaller(string file)
    {
        Process.Start(new ProcessStartInfo(file, "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-") { UseShellExecute = true });
    }

    public static bool InstalledWithSetup =>
        File.Exists(Path.Combine(AppContext.BaseDirectory, "unins000.exe"));
}
