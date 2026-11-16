using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Views;

/// <summary>Un grupo del árbol de aparatos.</summary>
public sealed class DeviceNode
{
    public string Icon { get; init; } = "";
    public string Title { get; init; } = "";
    public List<ScanDevice> Items { get; init; } = new();
}

/// <summary>Ventana "Router": aparatos de casa (escaneo), puertas del router, UPnP, velocidad y Wi-Fi.</summary>
public partial class RouterWindow : Window
{
    private RouterReport? _last;
    private List<ScanDevice> _devices = new();
    private CancellationTokenSource? _scanCancel;
    private bool _autoScanned;
    /// <summary>El último escaneo se hizo fuera de casa (cliente, oficina): no se guarda nada.</summary>
    private bool _awayScan;

    public RouterWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            ShowHistory();
            await RefreshAsync();
            if (IsHome()) ShowBook();
            // En casa, el escaneo se hace solo al abrir la ventana
            if (!_autoScanned && IsHome()) { _autoScanned = true; await ScanAsync(); }
        };
        Closed += (_, _) => _scanCancel?.Cancel();
    }

    private bool IsHome()
    {
        if (_last == null || _last.NetworkKey.Length == 0 || _last.Gateway.Length == 0) return false;
        string? homeKey = RouterCheck.HomeNetwork();
        return homeKey == null || homeKey == _last.NetworkKey;
    }

    private void ShowHistory()
    {
        var list = SpeedHistory.Load();
        list.Reverse();
        SpeedList.ItemsSource = list;
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
        UpnpTab.Header = $"  Puertos abiertos por UPnP ({r.Mappings.Count})  ";
        bool atHome = IsHome();
        BtnScan.IsEnabled = r.Gateway.Length > 0 && _scanCancel == null;
        BtnScan.ToolTip = atHome
            ? "Busca todos los aparatos encendidos de casa, su nombre, qué son y qué puertas tienen abiertas. No sale nada a Internet."
            : "Fuera de casa solo se escanea cuando lo pulsas tú (para revisar la red de un cliente). No se guarda nada ni se avisa de nada.";
        if (!atHome && _devices.Count == 0)
            ScanText.Text = "💼 Fuera de casa: el escaneo no se hace solo. Pulsa \"Escanear la red\" si quieres revisar esta red (no se guarda nada).";
    }

    // ------------------------------------------------------------------ escaneo de la red de casa
    private async void OnScan(object sender, RoutedEventArgs e) => await ScanAsync();

    private async Task ScanAsync()
    {
        if (_last == null || _last.Gateway.Length == 0 || _scanCancel != null) return;
        var r = _last;
        bool home = IsHome();
        _scanCancel = new CancellationTokenSource();
        var cancel = _scanCancel.Token;
        BtnScan.IsEnabled = false;
        ScanProgress.Visibility = Visibility.Visible;
        var started = DateTime.Now;
        try
        {
            var progress = new Progress<string>(t => ScanText.Text = t);
            var found = await Task.Run(() => NetScan.Run(r, progress, cancel), cancel);
            _awayScan = !home;
            if (home) _devices = DeviceBook.Merge(found, r.NetworkKey);
            else
            {
                // Red de otro (cliente, oficina): no se guarda en la libreta de casa. Los que
                // contestan salen en verde; en naranja, los que no se sabe qué son o tienen algo peligroso.
                foreach (var d in found) { d.Home = true; d.Away = true; d.FirstSeen = d.LastSeen = DateTime.Now; }
                _devices = found;
            }
            ShowDevices();
            int alive = _devices.Count(d => d.Answered);
            int heard = home ? DhcpNames.Load().Count : 0;
            ScanText.Text = $"{(home ? "" : "💼 Red fuera de casa (no se guarda). ")}Escaneado a las {DateTime.Now:HH:mm} en " +
                            $"{(DateTime.Now - started).TotalSeconds:0} s: {alive} aparato(s) encendidos." +
                            (home ? $" Nombres oídos al conectarse: {heard}." : "");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { ScanText.Text = "No se pudo escanear: " + ex.Message; }
        finally
        {
            _scanCancel = null;
            ScanProgress.Visibility = Visibility.Collapsed;
            BtnScan.IsEnabled = _last?.Gateway.Length > 0;
        }
    }

    /// <summary>Al abrir, se enseña lo que se recuerda del último escaneo (como "no responde" hasta escanear).</summary>
    private void ShowBook()
    {
        var book = DeviceBook.Load();
        string? homeKey = RouterCheck.HomeNetwork();
        if (homeKey == null || book.Count == 0) return;
        _devices = DeviceBook.Merge(new List<ScanDevice>(), homeKey);
        foreach (var d in _devices) d.Answered = true; // aún no se sabe: se pinta según lo que se sabía
        ShowDevices(remembered: true);
        ScanText.Text = "Lo que se vio en el último escaneo de casa (se vuelve a escanear solo si estás en casa).";
    }

    private static readonly (DeviceGroup Group, string Icon, string Title)[] Groups =
    {
        (DeviceGroup.Router, "📡", "Router"),
        (DeviceGroup.Ordenadores, "💻", "Ordenadores"),
        (DeviceGroup.Moviles, "📱", "Móviles y tablets"),
        (DeviceGroup.TeleConsolas, "📺", "Teles y consolas"),
        (DeviceGroup.Impresoras, "🖨", "Impresoras"),
        (DeviceGroup.Otros, "🔌", "Otros aparatos (domótica, cámaras, repetidores...)"),
        (DeviceGroup.Desconocidos, "❓", "Desconocidos"),
    };

    private void ShowDevices(bool remembered = false)
    {
        string? selected = (DeviceTree.SelectedItem as ScanDevice)?.Mac;
        var nodes = new List<DeviceNode>();
        foreach (var (group, icon, title) in Groups)
        {
            var items = _devices.Where(d => d.Group == group)
                .OrderBy(d => d.Answered ? 0 : 1).ThenBy(d => NetScan.IpOrder(d.Ip)).ToList();
            if (items.Count > 0) nodes.Add(new DeviceNode { Icon = icon, Title = $"{title} ({items.Count})", Items = items });
        }
        DeviceTree.ItemsSource = nodes;
        if (remembered)
        {
            CountHome.Text = $"{_devices.Count} recordados";
            CountNoName.Text = CountCheck.Text = CountGone.Text = "…";
        }
        else
        {
            CountHome.Text = $"{_devices.Count(d => d.State == DeviceState.DeCasa)} {(_awayScan ? "contestan" : "de casa")}";
            CountNoName.Text = $"{_devices.Count(d => d.State == DeviceState.SinNombre)} sin nombre";
            CountCheck.Text = $"{_devices.Count(d => d.State == DeviceState.Revisar)} revisar";
            CountGone.Text = $"{_devices.Count(d => d.State == DeviceState.NoResponde)} no responden";
        }
        var again = _devices.FirstOrDefault(d => d.Mac == selected);
        ShowCard(again);
        if (again != null) SelectInTree(again);
    }

    private void SelectInTree(ScanDevice d)
    {
        DeviceTree.UpdateLayout();
        foreach (var node in DeviceTree.Items.OfType<DeviceNode>())
        {
            if (!node.Items.Contains(d)) continue;
            if (DeviceTree.ItemContainerGenerator.ContainerFromItem(node) is TreeViewItem groupItem)
            {
                groupItem.IsExpanded = true;
                groupItem.UpdateLayout();
                if (groupItem.ItemContainerGenerator.ContainerFromItem(d) is TreeViewItem item) item.IsSelected = true;
            }
        }
    }

    private void OnDeviceSelected(object sender, RoutedPropertyChangedEventArgs<object> e) => ShowCard(e.NewValue as ScanDevice);

    private void ShowCard(ScanDevice? d)
    {
        DeviceCard.DataContext = d;
        DeviceCard.Visibility = d != null ? Visibility.Visible : Visibility.Collapsed;
        NoSelection.Visibility = d == null ? Visibility.Visible : Visibility.Collapsed;
        if (d == null) return;
        BtnWeb.Visibility = d.Answered && d.OpenPorts.Any(p => p is 80 or 443 or 8080 or 8443) ? Visibility.Visible : Visibility.Collapsed;
        BtnForget.Visibility = !d.Answered && !_awayScan ? Visibility.Visible : Visibility.Collapsed;
        BtnName.Visibility = _awayScan ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnNameDevice(object sender, RoutedEventArgs e)
    {
        if (DeviceCard.DataContext is not ScanDevice d) return;
        var dlg = new DeviceNameDialog(d) { Owner = this };
        if (dlg.ShowDialog() != true) return;
        DeviceBook.SetName(d.Mac, dlg.DeviceName, dlg.IsHome);
        d.Label = dlg.DeviceName.Trim();
        d.Home = dlg.IsHome;
        ShowDevices();
    }

    private void OnForgetDevice(object sender, RoutedEventArgs e)
    {
        if (DeviceCard.DataContext is not ScanDevice d) return;
        if (MessageBox.Show(this, $"¿Quitar \"{d.DisplayName}\" de la lista? Si vuelve a conectarse, saldrá como nuevo.", "Olvidar aparato",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        DeviceBook.Forget(d.Mac);
        _devices.Remove(d);
        ShowDevices();
    }

    private void OnOpenDeviceWeb(object sender, RoutedEventArgs e)
    {
        if (DeviceCard.DataContext is not ScanDevice d) return;
        string url = d.OpenPorts.Contains(443) ? $"https://{d.Ip}/" : d.OpenPorts.Contains(80) ? $"http://{d.Ip}/" :
                     d.OpenPorts.Contains(8443) ? $"https://{d.Ip}:8443/" : $"http://{d.Ip}:8080/";
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
    }

    private async void OnSpeed(object sender, RoutedEventArgs e)
    {
        BtnSpeed.IsEnabled = false;
        try
        {
            var progress = new Progress<string>(t => SpeedText.Text = "Velocidad: " + t);
            var r = await SpeedTest.RunAsync(_last?.Gateway ?? "", progress);
            var sample = SpeedSample.From(r, _last?.NetworkKey ?? "", manual: true);
            sample.Problem = SpeedHistory.Evaluate(sample, SpeedHistory.Load());
            SpeedHistory.Add(sample);
            SpeedText.Text = $"Velocidad ({DateTime.Now:HH:mm}): {r.Text}" + (sample.Bad ? $"\n⚠ {sample.Problem}" : "");
            SpeedText.Foreground = sample.Bad ? System.Windows.Media.Brushes.Red : System.Windows.Media.Brushes.Black;
            ShowHistory();
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
        _ = ScanAsync();
    }

    private void OnOpenAdmin(object sender, RoutedEventArgs e)
    {
        if (_last == null || _last.Gateway.Length == 0) return;
        bool https = _last.Ports.Any(p => p.Port == 443 && p.Open);
        try { Process.Start(new ProcessStartInfo($"{(https ? "https" : "http")}://{_last.Gateway}/") { UseShellExecute = true }); }
        catch { }
    }
}
