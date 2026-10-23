using System.Windows;
using FirewallFamiliar.Core;
using Microsoft.Win32;

namespace FirewallFamiliar.Views;

/// <summary>Crear o editar una regla avanzada.</summary>
public partial class AdvancedRuleDialog : Window
{
    private readonly AdvancedRule _rule;

    public AdvancedRuleDialog(AdvancedRule rule)
    {
        InitializeComponent();
        _rule = rule;

        TxtName.Text = rule.Name;
        CmbAction.SelectedIndex = rule.Action == RuleAction.Permitir ? 1 : 0;
        CmbDirection.SelectedIndex = (int)rule.Direction;
        CmbProtocol.SelectedIndex = (int)rule.Protocol;
        TxtAddresses.Text = rule.RemoteAddresses;
        TxtRemotePorts.Text = rule.RemotePorts;
        TxtLocalPorts.Text = rule.LocalPorts;
        TxtApp.Text = rule.AppPath;
        ChkEnabled.IsChecked = rule.Enabled;
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Elige el programa", Filter = "Programas (*.exe)|*.exe" };
        if (dlg.ShowDialog(this) == true) TxtApp.Text = dlg.FileName;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var test = new AdvancedRule
        {
            Id = _rule.Id,
            Name = TxtName.Text.Trim().Length == 0 ? "Regla sin nombre" : TxtName.Text.Trim(),
            Action = CmbAction.SelectedIndex == 1 ? RuleAction.Permitir : RuleAction.Bloquear,
            Direction = (RuleDirection)CmbDirection.SelectedIndex,
            Protocol = (RuleProtocol)CmbProtocol.SelectedIndex,
            RemoteAddresses = TxtAddresses.Text.Trim(),
            RemotePorts = TxtRemotePorts.Text.Trim(),
            LocalPorts = TxtLocalPorts.Text.Trim(),
            AppPath = TxtApp.Text.Trim(),
            Enabled = ChkEnabled.IsChecked == true
        };

        string? error = test.Validate();
        if (error != null)
        {
            MessageBox.Show(this, error, "Revisa la regla", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _rule.Name = test.Name;
        _rule.Action = test.Action;
        _rule.Direction = test.Direction;
        _rule.Protocol = test.Protocol;
        _rule.RemoteAddresses = test.RemoteAddresses;
        _rule.RemotePorts = test.RemotePorts;
        _rule.LocalPorts = test.LocalPorts;
        _rule.AppPath = test.AppPath;
        _rule.Enabled = test.Enabled;
        DialogResult = true;
    }
}
