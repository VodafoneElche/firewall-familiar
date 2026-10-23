using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using FirewallFamiliar.Core;
using FirewallFamiliar.Models;

namespace FirewallFamiliar;

public partial class MainWindow : Window
{
    private const int MaxConsoleLines = 500;

    private readonly TrafficMonitor _traffic = new();
    private readonly ProcessMonitor _processes = new();

    private readonly ObservableCollection<AppRow> _apps = new();
    private readonly Dictionary<int, AppRow> _appsByPid = new();
    private readonly ObservableCollection<ConnRow> _conns = new();
    private readonly Dictionary<string, ConnRow> _connsByKey = new();

    private readonly DispatcherTimer _fastTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DispatcherTimer _slowTimer = new() { Interval = TimeSpan.FromSeconds(2) };

    private long _lastTotalIn = -1, _lastTotalOut = -1;
    private DateTime _lastSlowTick = DateTime.UtcNow;
    private bool _refreshing;
    private bool _firstRefreshDone;
    private readonly HashSet<int> _announcedNetwork = new();
    private readonly Dictionary<int, (long In, long Out)> _lastBytes = new();
    private string? _connFilterProgram;

    public MainWindow()
    {
        InitializeComponent();

        AppsList.ItemsSource = _apps;
        ConnList.ItemsSource = _conns;

        var appsView = CollectionViewSource.GetDefaultView(_apps);
        appsView.Filter = FilterApp;
        appsView.SortDescriptions.Add(new SortDescription(nameof(AppRow.Name), ListSortDirection.Ascending));
        if (appsView is ICollectionViewLiveShaping live && live.CanChangeLiveSorting)
        {
            live.IsLiveSorting = true;
            live.IsLiveFiltering = true;
            live.LiveFilteringProperties.Add(nameof(AppRow.UsesNetwork));
        }

        var connView = CollectionViewSource.GetDefaultView(_conns);
        connView.Filter = FilterConn;
        connView.SortDescriptions.Add(new SortDescription(nameof(ConnRow.Program), ListSortDirection.Ascending));

        _fastTimer.Tick += (_, _) => OnFastTick();
        _slowTimer.Tick += async (_, _) => await RefreshListsAsync();

        _traffic.Error += msg => Dispatcher.BeginInvoke(() => Log("⚠ " + msg));

        UpdateFilterVisibility();
    }

    // =====================================================================
    // Arranque y cierre
    // =====================================================================

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Log("Firewall Familiar se ha iniciado (versión " + typeof(App).Assembly.GetName().Version?.ToString(3) + ").");
        Log("Modo actual: SOLO MONITOR. Se muestra el tráfico, pero todavía no se bloquea nada.");

        _traffic.Start();
        StatusTraffic.Text = _traffic.IsRunning
            ? "Monitor de tráfico: activo"
            : "Monitor de tráfico: solo totales (sin detalle por programa)";
        if (_traffic.IsRunning) Log("Monitor de tráfico por programa activo.");

        await RefreshListsAsync();
        _fastTimer.Start();
        _slowTimer.Start();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        _fastTimer.Stop();
        _slowTimer.Stop();
        _traffic.Dispose();
    }

    private void OnExit(object sender, RoutedEventArgs e) => Close();

    // =====================================================================
    // Cada segundo: gráficas y medidores
    // =====================================================================

    private void OnFastTick()
    {
        long totalIn, totalOut;
        if (_traffic.IsRunning)
        {
            totalIn = _traffic.TotalIn;
            totalOut = _traffic.TotalOut;
        }
        else
        {
            // Plan B: contadores de las tarjetas de red (sin detalle por programa)
            (totalIn, totalOut) = ReadInterfaceTotals();
            if (StatusTraffic.Text.EndsWith("activo"))
                StatusTraffic.Text = "Monitor de tráfico: solo totales (sin detalle por programa)";
        }

        if (_lastTotalIn >= 0)
        {
            double rateIn = Math.Max(0, totalIn - _lastTotalIn);
            double rateOut = Math.Max(0, totalOut - _lastTotalOut);
            GraphIn.AddSample(rateIn, 0);
            GraphOut.AddSample(rateOut, 0);
            MeterIn.Update(rateIn, 0);
            MeterOut.Update(rateOut, 0);
            GraphAttacks.AddSample(0, 0);
        }
        _lastTotalIn = totalIn;
        _lastTotalOut = totalOut;
    }

    private static (long, long) ReadInterfaceTotals()
    {
        long rx = 0, tx = 0;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up ||
                    nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var s = nic.GetIPStatistics();
                rx += s.BytesReceived;
                tx += s.BytesSent;
            }
        }
        catch { }
        return (rx, tx);
    }

    // =====================================================================
    // Cada 2 segundos: procesos y conexiones
    // =====================================================================

    private async Task RefreshListsAsync()
    {
        if (_refreshing) return;
        _refreshing = true;
        try
        {
            var data = await Task.Run(() => (procs: _processes.Read(), conns: ConnectionMonitor.GetAll()));
            var traffic = _traffic.Snapshot();
            var now = DateTime.UtcNow;
            double seconds = Math.Max(0.5, (now - _lastSlowTick).TotalSeconds);
            _lastSlowTick = now;

            MergeProcesses(data.procs, data.conns, traffic, seconds);
            MergeConnections(data.conns);

            int hidden = _apps.Count(a => a.Kind == ProcessKind.Oculto);
            StatusCounts.Text = $"Procesos: {_apps.Count}   Ocultos: {hidden}   Conexiones: {_conns.Count(c => !c.IsListening)}   Puertos en escucha: {_conns.Count(c => c.IsListening)}";
            _firstRefreshDone = true;
        }
        catch (Exception ex)
        {
            Log("⚠ Error al leer procesos o conexiones: " + ex.Message);
        }
        finally
        {
            _refreshing = false;
        }
    }

    private void MergeProcesses(List<ProcessSnapshot> procs, List<ConnectionInfo> conns,
        Dictionary<int, (long In, long Out)> traffic, double seconds)
    {
        var connCount = conns.Where(c => !c.IsListening).GroupBy(c => c.Pid).ToDictionary(g => g.Key, g => g.Count());
        var listenCount = conns.Where(c => c.IsListening).GroupBy(c => c.Pid).ToDictionary(g => g.Key, g => g.Count());
        var seen = new HashSet<int>();

        foreach (var p in procs)
        {
            seen.Add(p.Pid);
            bool isNew = !_appsByPid.TryGetValue(p.Pid, out var row);
            if (isNew)
            {
                row = new AppRow(p.Pid);
                _appsByPid[p.Pid] = row;
                _apps.Add(row);
            }

            row!.Name = p.Name;
            row.Description = p.Description;
            row.Version = p.Version;
            row.Path = p.Path;
            row.ServiceNames = p.Services;
            row.Kind = p.Kind;
            row.Icon = p.Icon;
            row.Memory = p.Memory;
            row.Cpu = p.CpuPercent;
            row.Connections = connCount.GetValueOrDefault(p.Pid);
            row.Listening = listenCount.GetValueOrDefault(p.Pid);

            if (traffic.TryGetValue(p.Pid, out var t))
            {
                var last = _lastBytes.GetValueOrDefault(p.Pid);
                row.RateIn = (long)(Math.Max(0, t.In - last.In) / seconds);
                row.RateOut = (long)(Math.Max(0, t.Out - last.Out) / seconds);
                row.BytesIn = t.In;
                row.BytesOut = t.Out;
                _lastBytes[p.Pid] = t;
            }
            else
            {
                row.RateIn = row.RateOut = 0;
            }

            if (isNew && _firstRefreshDone)
            {
                string kind = p.Kind == ProcessKind.Oculto ? "  ⚠ OCULTO (sin ventana)" : "";
                Log($"Nuevo proceso: {p.Name} (PID {p.Pid}){kind}  {p.Path}");
            }

            if (row.UsesNetwork && _announcedNetwork.Add(p.Pid) && _firstRefreshDone)
            {
                string kind = p.Kind == ProcessKind.Oculto ? "  ⚠ proceso oculto" : "";
                Log($"{p.Name} (PID {p.Pid}) ha empezado a usar la red{kind}.");
            }
            else if (!_firstRefreshDone && row.UsesNetwork)
            {
                _announcedNetwork.Add(p.Pid);
            }
        }

        // Procesos que han terminado
        var dead = _appsByPid.Keys.Where(pid => !seen.Contains(pid)).ToList();
        foreach (var pid in dead)
        {
            var row = _appsByPid[pid];
            _apps.Remove(row);
            _appsByPid.Remove(pid);
            _lastBytes.Remove(pid);
            _announcedNetwork.Remove(pid);
            if (row.Kind == ProcessKind.Oculto || row.UsesNetwork)
                Log($"Ha terminado: {row.Name} (PID {pid}).");
        }
        _traffic.Forget(dead);
    }

    private void MergeConnections(List<ConnectionInfo> conns)
    {
        var seen = new HashSet<string>();
        foreach (var c in conns)
        {
            string key = $"{c.Pid}|{c.Protocol}|{c.Local}|{c.Remote}";
            if (!seen.Add(key)) continue;
            string program = _appsByPid.TryGetValue(c.Pid, out var app) ? app.Name : (c.Pid == 0 ? "Sistema" : "?");

            if (_connsByKey.TryGetValue(key, out var row))
            {
                row.State = c.State;
                row.Program = program;
            }
            else
            {
                row = new ConnRow(c, program);
                _connsByKey[key] = row;
                _conns.Add(row);
                if (!c.IsListening && c.RemoteAddress.Length > 0)
                    _ = ResolveNameAsync(row, c.RemoteAddress);
            }
        }

        foreach (var key in _connsByKey.Keys.Where(k => !seen.Contains(k)).ToList())
        {
            _conns.Remove(_connsByKey[key]);
            _connsByKey.Remove(key);
        }
    }

    private static readonly ConcurrentDictionary<string, Task<string>> DnsCache = new();

    /// <summary>Busca el nombre del equipo remoto (DNS inverso), sin bloquear la ventana.</summary>
    private static async Task ResolveNameAsync(ConnRow row, string address)
    {
        if (!IPAddress.TryParse(address, out var ip) || IPAddress.IsLoopback(ip) ||
            ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return;
        try
        {
            row.RemoteName = await DnsCache.GetOrAdd(address, async a =>
            {
                try { return (await Dns.GetHostEntryAsync(a)).HostName; }
                catch { return ""; }
            });
        }
        catch { }
    }

    // =====================================================================
    // Filtros, orden y pestañas
    // =====================================================================

    private bool FilterApp(object o)
    {
        var a = (AppRow)o;
        if (ChkHideWindows.IsChecked == true && a.Kind is ProcessKind.Servicio or ProcessKind.Sistema or ProcessKind.SegundoPlano) return false;
        if (ChkOnlyNetwork.IsChecked == true && !a.UsesNetwork) return false;
        string q = SearchBox.Text.Trim();
        return q.Length == 0 ||
               a.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               a.Description.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               a.Path.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               a.Pid.ToString() == q;
    }

    private bool FilterConn(object o)
    {
        var c = (ConnRow)o;
        if (ChkHideListening.IsChecked == true && c.IsListening) return false;
        if (_connFilterProgram != null && c.Program != _connFilterProgram) return false;
        string q = SearchBox.Text.Trim();
        return q.Length == 0 ||
               c.Program.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               c.Remote.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               c.RemoteName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               c.Local.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               c.Pid.ToString() == q;
    }

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (sender == SearchBox) _connFilterProgram = null;
        CollectionViewSource.GetDefaultView(_apps)?.Refresh();
        CollectionViewSource.GetDefaultView(_conns)?.Refresh();
    }

    private void OnTabChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source == Tabs) UpdateFilterVisibility();
    }

    private void UpdateFilterVisibility()
    {
        bool apps = Tabs.SelectedItem == TabApps;
        ChkHideWindows.Visibility = apps ? Visibility.Visible : Visibility.Collapsed;
        ChkOnlyNetwork.Visibility = apps ? Visibility.Visible : Visibility.Collapsed;
        ChkHideListening.Visibility = apps ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnShowApps(object sender, RoutedEventArgs e) => Tabs.SelectedItem = TabApps;

    private void OnShowConnections(object sender, RoutedEventArgs e)
    {
        _connFilterProgram = null;
        CollectionViewSource.GetDefaultView(_conns)?.Refresh();
        Tabs.SelectedItem = TabConnections;
    }

    /// <summary>Ordena una lista al pulsar la cabecera de una columna.</summary>
    private void OnHeaderClick(object sender, RoutedEventArgs e)
    {
        if (e.OriginalSource is not GridViewColumnHeader { Column: { } column } || sender is not ListView list) return;

        string? prop = column.Header switch
        {
            "Programa" => list == AppsList ? nameof(AppRow.Name) : nameof(ConnRow.Program),
            "Descripción" => nameof(AppRow.Description),
            "Tipo" => nameof(AppRow.Kind),
            "PID" => "Pid",
            "Memoria" => nameof(AppRow.Memory),
            "CPU %" => nameof(AppRow.Cpu),
            "Conex." => nameof(AppRow.Connections),
            "Recibido" => nameof(AppRow.BytesIn),
            "Enviado" => nameof(AppRow.BytesOut),
            "Ahora" => nameof(AppRow.RateIn),
            "Versión" => nameof(AppRow.Version),
            "Ruta" => nameof(AppRow.Path),
            "Servicios" => nameof(AppRow.ServiceNames),
            "Protocolo" => nameof(ConnRow.Protocol),
            "Dirección local" => nameof(ConnRow.Local),
            "Equipo remoto" => nameof(ConnRow.Remote),
            "Nombre remoto" => nameof(ConnRow.RemoteName),
            "Estado" => nameof(ConnRow.State),
            _ => null
        };
        if (prop == null) return;

        var view = CollectionViewSource.GetDefaultView(list.ItemsSource);
        var dir = ListSortDirection.Ascending;
        if (view.SortDescriptions.Count > 0 && view.SortDescriptions[0].PropertyName == prop &&
            view.SortDescriptions[0].Direction == ListSortDirection.Ascending)
            dir = ListSortDirection.Descending;
        // Las cifras se ordenan de mayor a menor la primera vez
        else if (prop is nameof(AppRow.Memory) or nameof(AppRow.Cpu) or nameof(AppRow.Connections)
                 or nameof(AppRow.BytesIn) or nameof(AppRow.BytesOut) or nameof(AppRow.RateIn)
                 && !(view.SortDescriptions.Count > 0 && view.SortDescriptions[0].PropertyName == prop))
            dir = ListSortDirection.Descending;

        view.SortDescriptions.Clear();
        view.SortDescriptions.Add(new SortDescription(prop, dir));
    }

    // =====================================================================
    // Menú contextual de programas
    // =====================================================================

    private AppRow? SelectedApp => AppsList.SelectedItem as AppRow;

    private void OnAppDoubleClick(object sender, MouseButtonEventArgs e) => OnShowAppConnections(sender, e);

    private void OnShowAppConnections(object sender, RoutedEventArgs e)
    {
        if (SelectedApp is not { } app) return;
        _connFilterProgram = app.Name;
        CollectionViewSource.GetDefaultView(_conns)?.Refresh();
        Tabs.SelectedItem = TabConnections;
        Log($"Mostrando las conexiones de {app.Name}. Pulsa \"Conexiones\" en la barra para verlas todas.");
    }

    private void OnOpenLocation(object sender, RoutedEventArgs e)
    {
        if (SelectedApp is not { Path.Length: > 0 } app) return;
        Process.Start("explorer.exe", $"/select,\"{app.Path}\"");
    }

    private void OnCopyPath(object sender, RoutedEventArgs e)
    {
        if (SelectedApp is { Path.Length: > 0 } app) Clipboard.SetText(app.Path);
    }

    private void OnSearchWeb(object sender, RoutedEventArgs e)
    {
        if (SelectedApp is not { } app) return;
        string file = string.IsNullOrEmpty(app.Path) ? app.Name : ProcessMonitor.FileName(app.Path);
        string url = "https://www.google.com/search?q=" + Uri.EscapeDataString(file + " qué es proceso");
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    private void OnKillProcess(object sender, RoutedEventArgs e)
    {
        if (SelectedApp is not { } app) return;
        var answer = MessageBox.Show(
            $"¿Seguro que quieres terminar \"{app.Name}\" (PID {app.Pid})?\n\n{app.Path}\n\n" +
            "Si es un componente de Windows, el equipo podría dejar de funcionar bien hasta reiniciar.",
            "Terminar proceso", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            using var p = Process.GetProcessById(app.Pid);
            p.Kill();
            Log($"Proceso terminado por el usuario: {app.Name} (PID {app.Pid}).");
        }
        catch (Exception ex)
        {
            Log($"⚠ No se pudo terminar {app.Name}: {ex.Message}");
        }
    }

    // =====================================================================
    // Consola de mensajes y varios
    // =====================================================================

    private void Log(string message)
    {
        ConsoleList.Items.Add($"{DateTime.Now:dd/MM/yyyy HH:mm:ss}  {message}");
        while (ConsoleList.Items.Count > MaxConsoleLines) ConsoleList.Items.RemoveAt(0);
        ConsoleList.ScrollIntoView(ConsoleList.Items[^1]);
    }

    private void OnClearConsole(object sender, RoutedEventArgs e) => ConsoleList.Items.Clear();

    private void OnToggleConsole(object sender, RoutedEventArgs e)
    {
        bool show = MenuConsole.IsChecked;
        ConsoleRow.Height = show ? new GridLength(130) : new GridLength(0);
        ConsoleList.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnAbout(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            "Firewall Familiar " + typeof(App).Assembly.GetName().Version?.ToString(3) + "\n\n" +
            "Inspirado en Sygate Personal Firewall.\n\n" +
            "Esta versión es solo un MONITOR: muestra qué programas usan la red y cuánto, " +
            "y señala en naranja los procesos ocultos (sin ventana, que no son servicios " +
            "ni forman parte de Windows). Todavía no bloquea nada.\n\n" +
            "Consejos:\n" +
            "• Doble clic en un programa para ver sus conexiones.\n" +
            "• Clic derecho para abrir su carpeta o buscar en Internet qué es.\n" +
            "• Pulsa en las cabeceras de las columnas para ordenar.",
            "Acerca de Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}

/// <summary>Una fila de la pestaña "Conexiones".</summary>
public sealed class ConnRow : INotifyPropertyChanged
{
    public ConnRow(ConnectionInfo c, string program)
    {
        Pid = c.Pid;
        Protocol = c.Protocol;
        Local = c.Local;
        Remote = c.Remote;
        _state = c.State;
        _program = program;
    }

    public int Pid { get; }
    public string Protocol { get; }
    public string Local { get; }
    public string Remote { get; }

    private string _program;
    public string Program { get => _program; set => Set(ref _program, value); }

    private string _state;
    public string State
    {
        get => _state;
        set { if (Set(ref _state, value)) PropertyChanged?.Invoke(this, new(nameof(IsListening))); }
    }

    public bool IsListening => State == "Escuchando";

    private string _remoteName = "";
    public string RemoteName { get => _remoteName; set => Set(ref _remoteName, value); }

    public event PropertyChangedEventHandler? PropertyChanged;

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value)) return false;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        return true;
    }
}
