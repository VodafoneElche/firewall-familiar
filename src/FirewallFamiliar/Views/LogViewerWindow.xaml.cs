using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using FirewallFamiliar.Core;
using Microsoft.Win32;

namespace FirewallFamiliar.Views;

/// <summary>
/// Visor de registros, como el "Security Log" y "Traffic Log" de Sygate: elige el día,
/// filtra y haz doble clic para ver la ficha de cualquier evento.
/// </summary>
public partial class LogViewerWindow : Window
{
    private readonly Action<ConsoleEvent> _showDetails;
    private List<LogEntry> _entries = new();
    private bool _loading;

    public LogViewerWindow(Action<ConsoleEvent> showDetails)
    {
        InitializeComponent();
        _showDetails = showDetails;
        Loaded += (_, _) => LoadDays();
    }

    private LogKind Kind => CmbKind.SelectedIndex == 1 ? LogKind.Trafico : LogKind.Seguridad;

    private void LoadDays()
    {
        _loading = true;
        var days = LogStore.Days(Kind);
        if (!days.Contains(DateTime.Today)) days.Insert(0, DateTime.Today);
        CmbDay.Items.Clear();
        foreach (var d in days)
            CmbDay.Items.Add(new ComboBoxItem { Content = d == DateTime.Today ? "Hoy" : d == DateTime.Today.AddDays(-1) ? "Ayer" : d.ToString("dddd d/MM/yyyy"), Tag = d });
        CmbDay.SelectedIndex = 0;
        _loading = false;
        _ = LoadAsync();
    }

    private async Task LoadAsync()
    {
        if (CmbDay.SelectedItem is not ComboBoxItem { Tag: DateTime day }) return;
        StatusText.Text = "Cargando...";
        var kind = Kind;
        try
        {
            _entries = await Task.Run(() => LogStore.Read(kind, day));
        }
        catch (Exception ex)
        {
            _entries = new();
            StatusText.Text = "No se pudo leer el registro: " + ex.Message;
            return;
        }
        _entries.Reverse(); // lo más reciente arriba
        List.ItemsSource = _entries;
        var view = CollectionViewSource.GetDefaultView(_entries);
        view.Filter = Filter;
        UpdateStatus();
    }

    private bool Filter(object o)
    {
        var e = (LogEntry)o;
        bool show = CmbShow.SelectedIndex switch
        {
            1 => e.Outcome == "Bloqueado" || e.Outcome == "Escaneo",
            2 => e.Outcome == "Permitido",
            3 => e.Outcome is "Escaneo" or "Sospechoso" or "Oculto",
            4 => e.Inbound,
            _ => true
        };
        if (!show) return false;
        string q = SearchBox.Text.Trim();
        return q.Length == 0 ||
               e.Text.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               (e.App ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) ||
               (e.Remote ?? "").Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void UpdateStatus()
    {
        int shown = List.Items.Count;
        int blocked = _entries.Count(e => e.Outcome == "Bloqueado");
        int alerts = _entries.Count(e => e.Outcome is "Escaneo" or "Sospechoso");
        StatusText.Text = $"{shown} de {_entries.Count} eventos.   Bloqueos: {blocked}   Avisos importantes: {alerts}" +
                          $"      Los registros se guardan {LogStore.KeepDays} días en {LogStore.Folder}";
    }

    private void OnKindChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded) LoadDays();
    }

    private void OnDayChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_loading && IsLoaded) _ = LoadAsync();
    }

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || List.ItemsSource == null) return;
        CollectionViewSource.GetDefaultView(_entries)?.Refresh();
        UpdateStatus();
    }

    private void OnRefresh(object sender, RoutedEventArgs e) => _ = LoadAsync();

    private void OnDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (List.SelectedItem is LogEntry entry) _showDetails(entry.ToEvent());
    }

    private void OnHeaderClick(object sender, RoutedEventArgs e)
    {
        if (e.OriginalSource is not GridViewColumnHeader { Column: { } column } || List.ItemsSource == null) return;
        string? prop = column.Header switch
        {
            "Hora" => nameof(LogEntry.Time),
            "Resultado" => nameof(LogEntry.Outcome),
            "Programa" => nameof(LogEntry.AppName),
            "Sentido" => nameof(LogEntry.DirectionText),
            "Equipo remoto" => nameof(LogEntry.RemoteText),
            "Para qué" => nameof(LogEntry.PortMeaning),
            "Protocolo" => nameof(LogEntry.Protocol),
            "Mensaje" => nameof(LogEntry.Text),
            _ => null
        };
        if (prop == null) return;
        var view = CollectionViewSource.GetDefaultView(_entries);
        var dir = view.SortDescriptions.Count > 0 && view.SortDescriptions[0].PropertyName == prop &&
                  view.SortDescriptions[0].Direction == ListSortDirection.Ascending
            ? ListSortDirection.Descending : ListSortDirection.Ascending;
        view.SortDescriptions.Clear();
        view.SortDescriptions.Add(new SortDescription(prop, dir));
    }

    /// <summary>Guarda lo que se ve en un CSV (se abre con Excel).</summary>
    private void OnExport(object sender, RoutedEventArgs e)
    {
        var day = CmbDay.SelectedItem is ComboBoxItem { Tag: DateTime d } ? d : DateTime.Today;
        var dlg = new SaveFileDialog
        {
            FileName = $"registro-{(Kind == LogKind.Seguridad ? "seguridad" : "trafico")}-{day:yyyy-MM-dd}.csv",
            Filter = "Archivo CSV (Excel)|*.csv",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Fecha;Hora;Resultado;Programa;Ruta;Sentido;Equipo remoto;Puerto local;Para qué;Protocolo;Mensaje");
            foreach (LogEntry x in List.Items)
                sb.AppendLine(string.Join(";", new[]
                {
                    x.Time.ToString("dd/MM/yyyy"), x.TimeText, x.Outcome, x.AppName, x.App ?? "", x.DirectionText,
                    x.RemoteText, x.LocalPort == 0 ? "" : x.LocalPort.ToString(), x.PortMeaning, x.Protocol, x.Text
                }.Select(Csv)));
            File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true)); // con BOM para que Excel vea los acentos
            StatusText.Text = "Guardado en " + dlg.FileName;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "No se pudo guardar: " + ex.Message, "Exportar", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static string Csv(string v) => v.Contains(';') || v.Contains('"') || v.Contains('\n')
        ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;

    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(LogStore.Folder);
        Process.Start("explorer.exe", $"\"{LogStore.Folder}\"");
    }
}
