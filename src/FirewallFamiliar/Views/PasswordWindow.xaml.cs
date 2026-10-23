using System.Windows;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Views;

/// <summary>Pide la contraseña (o una nueva, repetida dos veces).</summary>
public partial class PasswordWindow : Window
{
    private readonly AppSettings? _check;
    private readonly bool _newPassword;
    private int _tries;

    public string Password => Pwd1.Password;

    private PasswordWindow(string message, AppSettings? check, bool newPassword)
    {
        InitializeComponent();
        Message.Text = message;
        _check = check;
        _newPassword = newPassword;
        if (newPassword)
        {
            Label1.Text = "Nueva contraseña (déjala vacía para quitarla):";
            ConfirmPanel.Visibility = Visibility.Visible;
        }
        Loaded += (_, _) => Pwd1.Focus();
    }

    /// <summary>Pide la contraseña actual. Devuelve true si no hay contraseña o si es correcta.</summary>
    public static bool Ask(Window? owner, AppSettings settings, string why)
    {
        if (!settings.HasPassword) return true;
        var w = new PasswordWindow(why, settings, false);
        if (owner is { IsVisible: true }) w.Owner = owner; else w.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        return w.ShowDialog() == true;
    }

    /// <summary>Pide una contraseña nueva. Devuelve null si se cancela.</summary>
    public static string? AskNew(Window? owner)
    {
        var w = new PasswordWindow("Elige la contraseña que protegerá Firewall Familiar. No la compartas con los niños.", null, true);
        if (owner is { IsVisible: true }) w.Owner = owner; else w.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        return w.ShowDialog() == true ? w.Password : null;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        if (_newPassword)
        {
            if (Pwd1.Password != Pwd2.Password) { ShowError("Las dos contraseñas no coinciden."); return; }
            if (Pwd1.Password.Length is > 0 and < 4) { ShowError("Usa al menos 4 caracteres."); return; }
            DialogResult = true;
            return;
        }
        if (_check!.CheckPassword(Pwd1.Password)) { DialogResult = true; return; }
        _tries++;
        Pwd1.Clear();
        ShowError(_tries >= 3 ? "Contraseña incorrecta otra vez." : "Contraseña incorrecta.");
        if (_tries >= 5) DialogResult = false;
    }

    private void ShowError(string text)
    {
        Error.Text = text;
        Error.Visibility = Visibility.Visible;
    }
}
