using System;
using System.Windows;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Views;

/// <summary>Ajustes del SOC familiar: a qué buzón de Google Drive manda este PC sus informes y avisos.</summary>
public partial class SocWindow : Window
{
    private readonly AppSettings _settings;
    private readonly Func<RuleSet> _rules;

    public SocWindow(Window owner, AppSettings settings, Func<RuleSet> rules)
    {
        InitializeComponent();
        Owner = owner;
        _settings = settings;
        _rules = rules;
        UrlBox.Text = settings.SocUrl;
        KeyBox.Text = settings.SocKey;
        NameBox.Text = settings.SocName.Length > 0 ? settings.SocName : Environment.MachineName;
        Status.Text = settings.SocEnabled ? "Activado." : "Desactivado: rellena la dirección y la clave para activarlo.";
    }

    /// <summary>Ajustes tal como están escritos ahora en la ventana (sin guardar).</summary>
    private AppSettings Current() => new()
    {
        SocUrl = UrlBox.Text.Trim(),
        SocKey = KeyBox.Text.Trim(),
        SocName = NameBox.Text.Trim() == Environment.MachineName ? "" : NameBox.Text.Trim()
    };

    private bool Check(AppSettings s)
    {
        if (s.SocUrl.Length == 0 && s.SocKey.Length == 0) return true; // desactivar
        if (!s.SocEnabled)
        {
            Show("Falta la clave, o la dirección no empieza por https://", true);
            return false;
        }
        return true;
    }

    private void Show(string text, bool error)
    {
        Status.Text = text;
        Status.Foreground = error ? System.Windows.Media.Brushes.Firebrick : System.Windows.Media.Brushes.DarkGreen;
    }

    private async void OnTest(object sender, RoutedEventArgs e)
    {
        var s = Current();
        if (!Check(s) || !s.SocEnabled) return;
        BtnTest.IsEnabled = false;
        Show("Probando...", false);
        string? error = await SocClient.SendAsync(s, "latido", new { prueba = true }, 40);
        BtnTest.IsEnabled = true;
        Show(error == null ? "✔ El buzón ha recibido la prueba. Ya puedes guardar." : "✖ " + error, error != null);
    }

    private async void OnSendReport(object sender, RoutedEventArgs e)
    {
        var s = Current();
        if (!Check(s) || !s.SocEnabled) return;
        BtnReport.IsEnabled = false;
        try
        {
            var progress = new Progress<string>(t => Show(t, false));
            string md = await AnalysisReport.BuildAsync(DateTime.Today, DateTime.Today, _rules(), Array.Empty<ProcessSummary>(), progress);
            Show("Enviando el informe...", false);
            var data = new { nombre = $"{DateTime.Today:yyyy-MM-dd} {s.SocComputer} (hasta las {DateTime.Now:HH.mm}).md", contenido = md, dia = DateTime.Today.ToString("yyyy-MM-dd") };
            string? error = await SocClient.SendAsync(s, "informe", data, 120);
            Show(error == null ? "✔ Informe enviado. Lo verás en la carpeta de este PC en el Drive." : "✖ " + error, error != null);
        }
        catch (Exception ex) { Show("✖ " + ex.Message, true); }
        finally { BtnReport.IsEnabled = true; }
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        var s = Current();
        if (!Check(s)) return;
        _settings.SocUrl = s.SocUrl;
        _settings.SocKey = s.SocKey;
        _settings.SocName = s.SocName;
        DialogResult = true;
    }
}
