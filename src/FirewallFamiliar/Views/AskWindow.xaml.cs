using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Media;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Views;

/// <summary>Respuesta del usuario a la pregunta "¿permitir esta conexión?".</summary>
public sealed record AskAnswer(bool Allow, bool Remember);

/// <summary>
/// Ventana emergente al estilo Sygate: aparece abajo a la derecha cuando un programa
/// sin regla intenta conectarse, y pregunta si se le deja.
/// </summary>
public partial class AskWindow : Window
{
    public AskAnswer? Answer { get; private set; }

    public AskWindow(BlockedConnection c, ImageSource? icon, string description, bool hidden)
    {
        InitializeComponent();

        string name = string.IsNullOrEmpty(c.AppPath) ? "Programa desconocido" : Path.GetFileName(c.AppPath);
        AppName.Text = name;
        AppDescription.Text = description;
        AppPath.Text = c.AppPath;
        AppIcon.Source = icon;
        string meaning = Ports.Describe(c.RemotePort, c.Protocol);
        Remote.Text = c.RemoteAddress == null ? "(desconocido)"
            : $"{c.RemoteAddress}  puerto {c.RemotePort}{(meaning.Length > 0 ? " (" + meaning + ")" : "")}";
        Protocol.Text = c.Protocol;

        if (hidden)
        {
            Warning.Text = "⚠ Este programa se está ejecutando oculto (sin ventana). Si no sabes qué es, mejor bloquéalo.";
            Warning.Visibility = Visibility.Visible;
        }

        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Right - ActualWidth - 12;
            Top = area.Bottom - ActualHeight - 12;
            SystemSounds();
        };

        if (c.RemoteAddress != null)
        {
            _ = ResolveAsync(c.RemoteAddress);
            _ = OwnerAsync(c.RemoteAddress);
        }
        else OwnerText.Text = "";
    }

    private async System.Threading.Tasks.Task ResolveAsync(IPAddress ip)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            RemoteName.Text = entry.HostName;
        }
        catch
        {
            RemoteName.Text = "(sin nombre)";
        }
    }

    private async System.Threading.Tasks.Task OwnerAsync(IPAddress ip)
    {
        var owner = await IpInfo.LookupAsync(ip);
        OwnerText.Text = owner.Note.Length > 0 ? "(no se pudo consultar)"
            : owner.Country.Length > 0 && IpInfo.Special(ip) == null ? $"{owner.Organization} ({owner.Country})"
            : owner.Organization;
    }

    private static void SystemSounds()
    {
        try { System.Media.SystemSounds.Exclamation.Play(); } catch { }
    }

    private void OnAllow(object sender, RoutedEventArgs e)
    {
        Answer = new AskAnswer(true, Remember.IsChecked == true);
        Close();
    }

    private void OnBlock(object sender, RoutedEventArgs e)
    {
        Answer = new AskAnswer(false, Remember.IsChecked == true);
        Close();
    }
}
