using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using FirewallFamiliar.Core;
using Microsoft.Win32;

namespace FirewallFamiliar.Views;

/// <summary>Editor de reglas: por programa y avanzadas (puertos e IP).</summary>
public partial class RulesWindow : Window
{
    public static readonly RuleAction Permitir = RuleAction.Permitir;
    public static readonly RuleAction Bloquear = RuleAction.Bloquear;

    private readonly RuleSet _rules;
    private readonly ObservableCollection<AppRuleRow> _apps = new();
    private readonly ObservableCollection<AdvancedRule> _advanced;

    /// <summary>Las reglas editadas. Solo tiene valor si el usuario pulsa Aceptar.</summary>
    public RuleSet? Result { get; private set; }

    public RulesWindow(RuleSet current)
    {
        InitializeComponent();

        // Se trabaja sobre una copia: si se cancela, no cambia nada.
        _rules = JsonSerializer.Deserialize<RuleSet>(JsonSerializer.Serialize(current))!;

        foreach (var a in _rules.Apps.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase))
            _apps.Add(new AppRuleRow(a));
        AppsList.ItemsSource = _apps;

        _advanced = new ObservableCollection<AdvancedRule>(_rules.Advanced);
        AdvancedList.ItemsSource = _advanced;

        ChkWindows.IsChecked = _rules.AllowWindowsComponents;
    }

    private void OnAddApp(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Elige el programa",
            Filter = "Programas (*.exe)|*.exe",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
        };
        if (dlg.ShowDialog(this) != true) return;
        if (_apps.Any(a => string.Equals(a.Path, dlg.FileName, StringComparison.OrdinalIgnoreCase))) return;
        var rule = new AppRule { Path = dlg.FileName, Action = RuleAction.Bloquear };
        _apps.Add(new AppRuleRow(rule));
    }

    private void OnRemoveApp(object sender, RoutedEventArgs e)
    {
        if (AppsList.SelectedItem is AppRuleRow row) _apps.Remove(row);
    }

    private void OnNewAdvanced(object sender, RoutedEventArgs e)
    {
        var rule = new AdvancedRule();
        var dlg = new AdvancedRuleDialog(rule) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            _advanced.Insert(0, rule);
            AdvancedList.SelectedItem = rule;
        }
    }

    private void OnEditAdvanced(object sender, RoutedEventArgs e)
    {
        if (AdvancedList.SelectedItem is not AdvancedRule rule) return;
        var copy = JsonSerializer.Deserialize<AdvancedRule>(JsonSerializer.Serialize(rule))!;
        var dlg = new AdvancedRuleDialog(copy) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            int i = _advanced.IndexOf(rule);
            _advanced[i] = copy;
            AdvancedList.SelectedItem = copy;
        }
    }

    private void OnDeleteAdvanced(object sender, RoutedEventArgs e)
    {
        if (AdvancedList.SelectedItem is AdvancedRule rule &&
            MessageBox.Show(this, $"¿Borrar la regla \"{rule.Name}\"?", "Borrar regla",
                MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            _advanced.Remove(rule);
    }

    private void OnUp(object sender, RoutedEventArgs e) => Move(-1);
    private void OnDown(object sender, RoutedEventArgs e) => Move(+1);

    private void Move(int delta)
    {
        if (AdvancedList.SelectedItem is not AdvancedRule rule) return;
        int i = _advanced.IndexOf(rule), j = i + delta;
        if (j < 0 || j >= _advanced.Count) return;
        _advanced.Move(i, j);
        AdvancedList.SelectedItem = rule;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        _rules.Apps = _apps.Select(a => new AppRule { Path = a.Path, Action = a.Action, Created = a.Created }).ToList();
        _rules.Advanced = _advanced.ToList();
        _rules.AllowWindowsComponents = ChkWindows.IsChecked == true;
        Result = _rules;
        DialogResult = true;
    }
}

/// <summary>Fila editable de la pestaña "Programas".</summary>
public sealed class AppRuleRow : INotifyPropertyChanged
{
    public AppRuleRow(AppRule rule)
    {
        Path = rule.Path;
        _action = rule.Action;
        Created = rule.Created;
        Icon = ProcessMonitor.LoadIcon(rule.Path);
    }

    public string Path { get; }
    public string Name => System.IO.Path.GetFileName(Path);
    public DateTime Created { get; }
    public ImageSource? Icon { get; }

    private RuleAction _action;
    public RuleAction Action
    {
        get => _action;
        set { _action = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Action))); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
