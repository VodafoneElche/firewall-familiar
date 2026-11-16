using System.Windows;
using System.Windows.Controls;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Views;

/// <summary>Ventanita para ponerle nombre a un aparato de casa y decir si es de casa.</summary>
public sealed class DeviceNameDialog : Window
{
    private readonly TextBox _name;
    private readonly CheckBox _home;

    public string DeviceName => _name.Text.Trim();
    public bool IsHome => _home.IsChecked == true;

    public DeviceNameDialog(ScanDevice d)
    {
        Title = "Ponerle nombre al aparato";
        Width = 460;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;

        var panel = new StackPanel { Margin = new Thickness(14) };
        panel.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8),
            Text = $"{d.Ip}  ·  {d.Mac}\n{d.VendorText}{(d.TypeText.Length > 0 ? "  ·  " + d.TypeText : "")}"
        });
        panel.Children.Add(new TextBlock { Text = "Nombre (por ejemplo: Móvil de Elena, PS3 del salón, Tele de la cocina):" });
        _name = new TextBox { Text = d.Label.Length > 0 ? d.Label : d.HostName, Margin = new Thickness(0, 4, 0, 8), Padding = new Thickness(3) };
        panel.Children.Add(_name);
        _home = new CheckBox
        {
            Content = "Es de casa (lo conozco y está bien que esté conectado)",
            IsChecked = d.Label.Length == 0 || d.Home, Margin = new Thickness(0, 0, 0, 12)
        };
        panel.Children.Add(_home);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var ok = new Button { Content = "Guardar", IsDefault = true, Padding = new Thickness(14, 3, 14, 3), Margin = new Thickness(0, 0, 8, 0) };
        ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button { Content = "Cancelar", IsCancel = true, Padding = new Thickness(14, 3, 14, 3) };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        panel.Children.Add(buttons);
        Content = panel;
        Loaded += (_, _) => { _name.Focus(); _name.SelectAll(); };
    }
}
