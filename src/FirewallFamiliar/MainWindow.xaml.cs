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

        _traffic.Start();
        StatusTraffic.Text = _traffic.IsRunning
            ? "Monitor de tráfico: activo"
            : "Monitor de tráfico: solo totales (sin detalle por programa)";
        if (_traffic.IsRunning) Log("Monitor de tráfico por programa activo.");

        await RefreshListsAsync();
        InitSecurity();
        InitFirewall();
        _fastTimer.Start();
        _slowTimer.Start();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        _fastTimer.Stop();
        _slowTimer.Stop();
        _traffic.Dispose();
        _firewall.Dispose(); // al cerrar se quitan todos los filtros y la red queda como estaba
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
            GraphIn.AddSample(rateIn, _blockedInThisSecond);
            GraphOut.AddSample(rateOut, _blockedOutThisSecond);
            MeterIn.Update(rateIn, _blockedInThisSecond);
            MeterOut.Update(rateOut, _blockedOutThisSecond);
            _blockedInThisSecond = _blockedOutThisSecond = 0;
            GraphAttacks.AddSample(_attemptsThisSecond, _scansThisSecond);
            _attemptsThisSecond = _scansThisSecond = 0;
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
            row.Rule = p.Path.Length > 0 ? _rules.ActionFor(p.Path) : RuleAction.Preguntar;
            if (p.Path.Length > 0 && IsWindowsComponent(p.Path)) NoteWindowsComponent(p.Path);
            if (p.Path.Length > 0) row.Signature = Signature.Get(p.Path);
            CheckSuspicious(row);

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

            // Solo se avisa de los procesos nuevos que arrancan ocultos; el resto
            // (pestañas del navegador, componentes de Windows...) llenaría la consola.
            if (isNew && _firstRefreshDone && p.Kind == ProcessKind.Oculto)
                Log(new ConsoleEvent { Text = $"⚠ Nuevo proceso oculto: {p.Name} (PID {p.Pid})  {p.Path}", AppPath = p.Path, Pid = p.Pid, Outcome = "Oculto" });

            if (row.UsesNetwork && _announcedNetwork.Add(p.Pid) && _firstRefreshDone)
            {
                string kind = p.Kind == ProcessKind.Oculto ? "  ⚠ proceso oculto" : "";
                // Primera conexión de ese programa, para poder enseñar con quién habla
                var first = conns.FirstOrDefault(c => c.Pid == p.Pid && !c.IsListening && c.RemoteAddress.Length > 0);
                IPAddress.TryParse(first?.RemoteAddress, out var firstIp);
                Log(new ConsoleEvent
                {
                    Text = $"{p.Name} (PID {p.Pid}) ha empezado a usar la red{kind}.",
                    AppPath = p.Path, Pid = p.Pid, Outcome = "Red",
                    RemoteAddress = firstIp, RemotePort = first?.RemotePort ?? 0, Protocol = first?.Protocol ?? ""
                });
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
                Log(new ConsoleEvent { Text = $"Ha terminado: {row.Name} (PID {pid}).", AppPath = row.Path, Pid = pid });
        }
        _traffic.Forget(dead);
    }

    private void MergeConnections(List<ConnectionInfo> conns)
    {
        var seen = new HashSet<string>();
        // Puertos en escucha de cada programa: si una conexión llega a uno de ellos, es entrante
        var listening = conns.Where(c => c.IsListening).Select(c => (c.Pid, c.LocalPort)).ToHashSet();
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
                {
                    _ = ResolveNameAsync(row, c.RemoteAddress);
                    LogTrafficConnection(c, app, c.Protocol.StartsWith("TCP") && listening.Contains((c.Pid, c.LocalPort)));
                }
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
            "Firma" => nameof(AppRow.SignatureText),
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

    private void Log(string message) => Log(new ConsoleEvent { Text = message });

    private void Log(ConsoleEvent e)
    {
        if (e.AppPath == "") e = new ConsoleEvent
        {
            Time = e.Time, Text = e.Text, Pid = e.Pid, RemoteAddress = e.RemoteAddress, RemotePort = e.RemotePort,
            Protocol = e.Protocol, Inbound = e.Inbound, Outcome = e.Outcome
        };
        LogStore.Write(LogKind.Seguridad, LogEntry.From(e));
        ConsoleList.Items.Add(e);
        while (ConsoleList.Items.Count > MaxConsoleLines) ConsoleList.Items.RemoveAt(0);
        ConsoleList.ScrollIntoView(ConsoleList.Items[^1]);
    }

    /// <summary>Al pinchar en un mensaje con detalles, se abre su ficha.</summary>
    private void OnConsoleClick(object sender, MouseButtonEventArgs e)
    {
        var item = ItemsControl.ContainerFromElement(ConsoleList, (DependencyObject)e.OriginalSource) as ListBoxItem;
        if (item?.DataContext is ConsoleEvent ev && ev.HasDetails) ShowDetails(ev);
    }

    private void OnConnectionDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ConnList.SelectedItem is not ConnRow c) return;
        _appsByPid.TryGetValue(c.Pid, out var app);
        var parts = c.Remote.Length > 0 ? c.Remote : "";
        int colon = parts.LastIndexOf(':');
        IPAddress? ip = null;
        int port = 0;
        if (colon > 0)
        {
            IPAddress.TryParse(parts[..colon], out ip);
            int.TryParse(parts[(colon + 1)..], out port);
        }
        ShowDetails(new ConsoleEvent
        {
            Text = $"{c.Program}: conexión {c.State.ToLowerInvariant()} con {c.Remote}",
            AppPath = app?.Path, Pid = c.Pid, RemoteAddress = ip, RemotePort = port,
            Protocol = c.Protocol.Replace("v6", ""), Outcome = "Red"
        });
    }

    private void ShowDetails(ConsoleEvent ev)
    {
        AppRow? row = ev.AppPath == null ? null :
            (ev.Pid > 0 && _appsByPid.TryGetValue(ev.Pid, out var byPid) && string.Equals(byPid.Path, ev.AppPath, StringComparison.OrdinalIgnoreCase))
                ? byPid
                : _apps.FirstOrDefault(a => string.Equals(a.Path, ev.AppPath, StringComparison.OrdinalIgnoreCase));
        var win = new Views.EventDetailsWindow(ev, row, path => _rules.ActionFor(path), SetRuleFromDetails) { Owner = this };
        win.Show();
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
            "Muestra qué programas usan la red y cuánto, señala en naranja los procesos ocultos " +
            "y permite bloquear programas, puertos o direcciones IP.\n\n" +
            "Modos de seguridad:\n" +
            "• Sin preguntas: aplica tus reglas y deja pasar el resto.\n" +
            "• Preguntar: avisa cuando un programa nuevo quiere salir a Internet.\n" +
            "• Bloquear todo: corta la red al momento.\n\n" +
            "Si cierras Firewall Familiar, se quitan todos los bloqueos.\n\n" +
            "Consejos:\n" +
            "• Clic derecho en un programa para permitirlo o bloquearlo.\n" +
            "• Doble clic en un programa para ver sus conexiones.\n" +
            "• Clic derecho para abrir su carpeta o buscar en Internet qué es.\n" +
            "• Pincha en un mensaje de la consola con ⓘ para ver su ficha.\n" +
            "• Los programas en naranja fuerte son sospechosos: ocultos y sin firma, o en carpetas raras.\n" +
            "• El botón Registros guarda todo lo que ha pasado durante 30 días.\n" +
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
