using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Views;

/// <summary>Ventana "Router": puertas del router, puertos abiertos por UPnP, aparatos de casa y Wi-Fi.</summary>
public partial class RouterWindow : Window
{
    private RouterReport? _last;

    public RouterWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async void OnRefresh(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        BtnRefresh.IsEnabled = false;
        StatusText.Text = "Revisando el router (unos 10 segundos)...";
        try
        {
            var r = await Task.Run(() => RouterCheck.Run(true));
            _last = r;
            Show(r);
            StatusText.Text = $"Revisado a las {r.Time:HH:mm:ss}.";
        }
        catch (Exception ex) { StatusText.Text = "No se pudo revisar: " + ex.Message; }
        finally { BtnRefresh.IsEnabled = true; }
    }

    private void Show(RouterReport r)
    {
        if (r.Gateway.Length == 0)
            RouterText.Text = r.Error.Length > 0 ? r.Error : "No se ha encontrado el router.";
        else
        {
            string model = r.RouterModel.Length > 0 ? r.RouterModel : r.RouterVendor;
            var open = r.Ports.Where(p => p.Open).ToList();
            int bad = open.Count(p => p.Level >= 2) + (r.WifiLevel >= 2 ? 1 : 0);
            string? homeKey = RouterCheck.HomeNetwork();
            bool home = homeKey == null || homeKey == r.NetworkKey;
            BtnHome.IsEnabled = !home && r.NetworkKey.Length > 0;
            RouterText.Text = (home ? "🏠 Red de casa (avisa de todo). " : "💼 Fuera de casa: solo avisa de lo crítico. ") +
                              $"Router {r.Gateway}{(model.Length > 0 ? $" ({model})" : "")}. " +
                              (r.RouterSilent ? "No contesta a nada (una VPN o el Wi-Fi de invitados lo tapan)."
                               : bad == 0 ? "No se ve nada peligroso." : $"⚠ Hay {bad} cosa(s) que conviene revisar.");
        }
        WifiText.Text = "Wi-Fi: " + (r.WifiSsid.Length > 0 ? $"\"{r.WifiSsid}\", " : "") +
                        (r.WifiAuth.Length > 0 ? $"{r.WifiAuth} / {r.WifiCipher}. " : "") + r.WifiNote;
        UpnpText.Text = "UPnP: " + (r.UpnpNote.Length > 0 ? r.UpnpNote : "no se ha podido mirar.");
        PortList.ItemsSource = r.Ports.Where(p => p.Open).OrderByDescending(p => p.Level).ThenBy(p => p.Port).ToList();
        UpnpList.ItemsSource = r.Mappings;
        DeviceList.ItemsSource = r.Devices;
        DevicesTitle.Text = $"Aparatos que este PC ve en la red ({r.Devices.Count}). Solo salen los que han hablado hace poco con este PC; puede haber más.";
    }

    private async void OnSpeed(object sender, RoutedEventArgs e)
    {
        BtnSpeed.IsEnabled = false;
        try
        {
            var progress = new Progress<string>(t => SpeedText.Text = "Velocidad: " + t);
            var r = await SpeedTest.RunAsync(_last?.Gateway ?? "", progress);
            SpeedText.Text = $"Velocidad ({DateTime.Now:HH:mm}): {r.Text}";
        }
        catch (Exception ex) { SpeedText.Text = "Velocidad: no se pudo medir: " + ex.Message; }
        finally { BtnSpeed.IsEnabled = true; }
    }

    private void OnSetHome(object sender, RoutedEventArgs e)
    {
        if (_last == null || _last.NetworkKey.Length == 0) return;
        if (MessageBox.Show(this, "¿Marcar esta red como la de casa? En casa se avisa de todo, también de cada aparato nuevo. " +
                "La red que era la de casa pasará a tratarse como \"fuera de casa\".", "Red de casa",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        RouterCheck.SetHomeNetwork(_last.NetworkKey);
        Show(_last);
    }

    private void OnOpenAdmin(object sender, RoutedEventArgs e)
    {
        if (_last == null || _last.Gateway.Length == 0) return;
        bool https = _last.Ports.Any(p => p.Port == 443 && p.Open);
        try { Process.Start(new ProcessStartInfo($"{(https ? "https" : "http")}://{_last.Gateway}/") { UseShellExecute = true }); }
        catch { }
    }
}
