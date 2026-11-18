using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
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
    private LanHistory.Data _history = new();
    private bool _settingWatch;

    public RouterWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            ShowHistory();
            await RefreshAsync();
            // En casa, el escaneo se hace solo al abrir la ventana
            if (!_autoScanned && IsHome()) { _autoScanned = true; await ScanAsync(); }
        };
        Closed += (_, _) => _scanCancel?.Cancel();
        HistoryCanvas.SizeChanged += (_, _) => DrawHistory();
        LatencyCanvas.SizeChanged += (_, _) => DrawHistory();
        MapCanvas.SizeChanged += (_, _) => DrawMap();
    }

    private bool IsHome()
    {
        if (_last == null || _last.NetworkKey.Length == 0 || _last.Gateway.Length == 0) return false;
        string? homeKey = RouterCheck.HomeNetwork();
        return homeKey == null || RouterCheck.SameNet(homeKey, _last.NetworkKey);
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
            bool home = homeKey == null || RouterCheck.IsHomeNetwork(r.NetworkKey) == true;
            BtnHome.IsEnabled = r.NetworkKey.Length > 0;
            BtnHome.Content = home ? "Esta NO es la red de casa" : "Esta es la red de casa";
            RouterText.Text = (home ? "🏠 Red de casa (avisa de todo). " : "💼 Fuera de casa: solo avisa de lo crítico. ") +
                              $"Router {r.Gateway}{(model.Length > 0 ? $" ({model})" : "")}, MAC {r.GatewayMac}" +
                              (!home && homeKey != null && homeKey != RouterCheck.NoHome ? $" (el de casa es {homeKey})" : "") + ". " +
                              (r.OtherAdapters.Count > 0 ? $"OJO: este PC está conectado a la vez a otra red por {string.Join(", ", r.OtherAdapters)} con las mismas direcciones; solo se mira la red de \"{r.Adapter}\". " : "") +
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
            // Cada escaneo muestra solo lo que hay AHORA (lo pidió Jose, para no liarse). En casa se
            // guarda en la libreta, pero de lo de antes solo sale lo que él ha pedido vigilar.
            if (home) _devices = DeviceBook.Merge(found, r.NetworkKey, r.Gateway).Where(d => d.Answered || d.Watch).ToList();
            else
            {
                // Red de otro (cliente, oficina): no se guarda en la libreta de casa. Los que
                // contestan salen en verde; en naranja, los que no se sabe qué son o tienen algo peligroso.
                foreach (var d in found)
                {
                    d.Home = true; d.Away = true; d.FirstSeen = d.LastSeen = DateTime.Now;
                    if (Family.Lookup(d.Mac) is { } fam) { d.Label = fam.Name; d.Kind = fam.Kind; NetScan.ApplyKind(d); }
                }
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

    private void ShowDevices(bool remembered = false)
    {
        string? selected = (DeviceCard.DataContext as ScanDevice)?.Mac;
        _history = _awayScan ? new LanHistory.Data() : LanHistory.Load();
        DeviceGrid.ItemsSource = _devices.OrderBy(d => d.Answered ? 0 : 1).ThenBy(d => NetScan.IpOrder(d.Ip)).ToList();
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
        DrawMap();
    }

    private void SelectInTree(ScanDevice d)
    {
        DeviceGrid.SelectedItem = d;
        DeviceGrid.ScrollIntoView(d);
    }

    private void OnDeviceSelected(object sender, SelectionChangedEventArgs e)
    {
        if (DeviceGrid.SelectedItem is ScanDevice d) ShowCard(d);
    }

    private void ShowCard(ScanDevice? d)
    {
        DeviceCard.DataContext = null; // así se vuelve a leer todo aunque sea el mismo aparato
        DeviceCard.DataContext = d;
        DeviceCard.Visibility = d != null ? Visibility.Visible : Visibility.Collapsed;
        NoSelection.Visibility = d == null ? Visibility.Visible : Visibility.Collapsed;
        if (d == null) return;
        BtnWeb.Visibility = d.Answered && d.OpenPorts.Any(p => p is 80 or 443 or 8080 or 8443) ? Visibility.Visible : Visibility.Collapsed;
        BtnForget.Visibility = !d.Answered && !_awayScan ? Visibility.Visible : Visibility.Collapsed;
        BtnName.Visibility = _awayScan ? Visibility.Collapsed : Visibility.Visible;
        _settingWatch = true;
        ChkWatch.IsChecked = d.Watch;
        _settingWatch = false;
        ChkWatch.Visibility = _awayScan || d.IsThisPc ? Visibility.Collapsed : Visibility.Visible;
        DrawHistory();
    }

    private void OnWatchChanged(object sender, RoutedEventArgs e)
    {
        if (_settingWatch || DeviceCard.DataContext is not ScanDevice d) return;
        d.Watch = ChkWatch.IsChecked == true;
        DeviceBook.SetWatch(d.Mac, d.Watch);
    }

    // ------------------------------------------------------------------ historial de la ficha
    private static readonly Brush OnBrush = Frozen("#2E9E44"), OffBrush = Frozen("#D32F2F"), NoDataBrush = Frozen("#ECEFF3"),
        LineBrush = Frozen("#1F6FD1"), GridBrush = Frozen("#E3E8EF");

    private static Brush Frozen(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }

    private void DrawHistory()
    {
        HistoryCanvas.Children.Clear();
        LatencyCanvas.Children.Clear();
        if (DeviceCard.DataContext is not ScanDevice d) return;
        var sum = _awayScan ? null : LanHistory.Of(_history, d.Mac);
        if (sum == null)
        {
            HistoryText.Text = _awayScan
                ? "Fuera de casa no se vigila nada."
                : "Aún no hay datos: la vigilancia mira la red cada 5 minutos, solo en casa y con este PC encendido.";
            return;
        }
        double w = HistoryCanvas.ActualWidth, h = HistoryCanvas.ActualHeight;
        int n = sum.Values.Length;
        if (w > 0)
        {
            double cw = w / n;
            for (int i = 0; i < n; i++)
            {
                int v = sum.Values[i];
                var r = new Rectangle { Width = Math.Max(cw + 0.5, 1), Height = h, Fill = v == -3 ? NoDataBrush : v == LanHistory.Off ? OffBrush : OnBrush };
                Canvas.SetLeft(r, i * cw);
                HistoryCanvas.Children.Add(r);
            }
        }
        HistoryText.Text = $"Contestaba en el {sum.OnPercent}% de las veces que se ha mirado ({sum.Checks}). " +
                           (sum.AvgMs >= 0 ? $"Tarda de media {sum.AvgMs} ms; lo peor, {sum.MaxMs} ms." : "No contesta al ping, así que no se sabe lo que tarda.") +
                           " Gris = no se miró (este PC apagado o fuera de casa).";

        double lw = LatencyCanvas.ActualWidth, lh = LatencyCanvas.ActualHeight;
        if (lw <= 0 || sum.MaxMs < 0) return;
        double top = Math.Max(20, sum.MaxMs * 1.1);
        foreach (double ms in new[] { 10.0, 50, 100, 500, 1000 }.Where(x => x < top))
        {
            double y = lh - ms / top * (lh - 4);
            LatencyCanvas.Children.Add(new Line { X1 = 0, X2 = lw, Y1 = y, Y2 = y, Stroke = GridBrush, StrokeThickness = 1 });
            var t = new TextBlock { Text = $"{ms} ms", FontSize = 9, Foreground = Brushes.Gray };
            Canvas.SetLeft(t, 2); Canvas.SetTop(t, y - 11);
            LatencyCanvas.Children.Add(t);
        }
        double step = lw / n;
        Polyline? line = null;
        for (int i = 0; i < n; i++)
        {
            int v = sum.Values[i];
            if (v < 0) { line = null; continue; }
            if (line == null) { line = new Polyline { Stroke = LineBrush, StrokeThickness = 1.5 }; LatencyCanvas.Children.Add(line); }
            line.Points.Add(new Point(i * step + step / 2, lh - v / top * (lh - 4)));
        }
    }

    // ------------------------------------------------------------------ mapa
    private void DrawMap()
    {
        MapCanvas.Children.Clear();
        double w = MapCanvas.ActualWidth, h = MapCanvas.ActualHeight;
        if (w < 100 || h < 100) return;
        if (_devices.Count == 0)
        {
            var t = new TextBlock { Text = "Escanea la red para ver el mapa.", Foreground = Brushes.Gray, FontSize = 14 };
            Canvas.SetLeft(t, 20); Canvas.SetTop(t, 20);
            MapCanvas.Children.Add(t);
            return;
        }
        var router = _devices.FirstOrDefault(d => d.IsGateway);
        var others = _devices.Where(d => d != router)
            .OrderBy(d => d.Group).ThenBy(d => NetScan.IpOrder(d.Ip)).ToList();
        double cx = w / 2, cy = h / 2;
        int n = others.Count;
        bool twoRings = n > 16;
        var nodes = new List<(ScanDevice D, double X, double Y)>();
        for (int i = 0; i < n; i++)
        {
            double a = -Math.PI / 2 + i * 2 * Math.PI / Math.Max(n, 1);
            double k = twoRings && i % 2 == 1 ? 0.62 : 1.0;
            double rx = (w / 2 - 110) * k, ry = (h / 2 - 45) * k;
            nodes.Add((others[i], cx + Math.Cos(a) * rx, cy + Math.Sin(a) * ry));
        }
        // Líneas primero (debajo de los aparatos)
        foreach (var (d, x, y) in nodes)
        {
            int v = Latency(d);
            var line = new Line
            {
                X1 = cx, Y1 = cy, X2 = x, Y2 = y, StrokeThickness = v >= 0 ? 2.5 : 1.5,
                Stroke = v >= 150 ? OffBrush : v >= 30 ? Frozen("#F08C00") : v >= 0 ? OnBrush : v == LanHistory.NoPing ? Frozen("#7FA889") : Frozen("#B0B6BE"),
                ToolTip = v >= 0 ? $"{v} ms" : v == LanHistory.NoPing ? "Encendido (no contesta al ping)" : "No contesta",
            };
            if (v == LanHistory.Off) line.StrokeDashArray = new DoubleCollection { 4, 3 };
            MapCanvas.Children.Add(line);
        }
        foreach (var (d, x, y) in nodes) AddNode(d, x, y, false);
        if (router != null) AddNode(router, cx, cy, true);
        else AddNode(new ScanDevice { Ip = _last?.Gateway ?? "", IsGateway = true, Group = DeviceGroup.Router, TypeText = "Router" }, cx, cy, true);
    }

    /// <summary>Lo último que se sabe de lo que tarda: la vigilancia del servicio o, si no hay, el escaneo.</summary>
    private int Latency(ScanDevice d)
    {
        if (!_awayScan && LanHistory.Latest(_history, d.Mac) is { } v) return v;
        return !d.Answered ? LanHistory.Off : d.PingMs >= 0 ? (int)d.PingMs : LanHistory.NoPing;
    }

    private void AddNode(ScanDevice d, double x, double y, bool big)
    {
        string name = d.DisplayName.Length > 32 ? d.DisplayName[..31] + "…" : d.DisplayName;
        var stack = new StackPanel();
        var top = new StackPanel { Orientation = Orientation.Horizontal };
        top.Children.Add(new Border
        {
            Width = big ? 14 : 11, Height = big ? 14 : 11, CornerRadius = new CornerRadius(2), Margin = new Thickness(0, 0, 5, 0),
            Background = Frozen(d.StateColor), VerticalAlignment = VerticalAlignment.Center
        });
        top.Children.Add(new TextBlock { Text = d.IsGateway ? "📡" : d.Icon, FontSize = big ? 26 : 22, Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center });
        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock { Text = name, FontWeight = FontWeights.SemiBold, FontSize = big ? 14 : 12 });
        texts.Children.Add(new TextBlock { Text = d.Ip, Foreground = Brushes.Gray, FontSize = 11 });
        top.Children.Add(texts);
        stack.Children.Add(top);
        var node = new Border
        {
            Child = stack, Background = Brushes.White, BorderBrush = Frozen(d.StateColor), BorderThickness = new Thickness(big ? 2 : 1.5),
            CornerRadius = new CornerRadius(4), Padding = new Thickness(6, 3, 6, 3), Cursor = Cursors.Hand, ToolTip = d.Tooltip,
        };
        node.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        Canvas.SetLeft(node, x - node.DesiredSize.Width / 2);
        Canvas.SetTop(node, y - node.DesiredSize.Height / 2);
        if (_devices.Contains(d))
            node.MouseLeftButtonUp += (_, _) => { Tabs.SelectedIndex = 0; ShowCard(d); SelectInTree(d); };
        MapCanvas.Children.Add(node);
    }

    private void OnNameDevice(object sender, RoutedEventArgs e)
    {
        if (DeviceCard.DataContext is not ScanDevice d) return;
        var dlg = new DeviceNameDialog(d) { Owner = this };
        if (dlg.ShowDialog() != true) return;
        DeviceBook.SetName(d.Mac, dlg.DeviceName, dlg.IsHome, dlg.Kind);
        d.Kind = dlg.Kind;
        NetScan.ApplyKind(d);
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
        if (IsHome())
        {
            if (MessageBox.Show(this, "¿Esta red NO es la de casa (oficina, cliente...)? Se tratará como \"fuera de casa\": " +
                    "solo se avisa de lo crítico y no se vigilan sus aparatos. Cuando estés en casa, pulsa \"Esta es la red de casa\".",
                    "Red de casa", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            RouterCheck.SetHomeNetwork(RouterCheck.NoHome);
            _devices = new List<ScanDevice>();
            _awayScan = true;
            ShowDevices();
            Show(_last);
            return;
        }
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
