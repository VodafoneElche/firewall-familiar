using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using FirewallFamiliar.Core;
using FirewallFamiliar.Models;

namespace FirewallFamiliar.Views;

/// <summary>
/// Ficha de un mensaje de la consola: qué programa era, con quién quería conectarse
/// y a quién pertenece esa dirección, explicado en lenguaje sencillo.
/// </summary>
public partial class EventDetailsWindow : Window
{
    private readonly ConsoleEvent _event;
    private readonly AppRow? _row;
    private readonly Func<string, RuleAction> _getRule;
    private readonly Action<string, RuleAction> _setRule;

    private string _appLabel = "";
    private string _ownerLabel = "";
    private string _serverName = "";

    public EventDetailsWindow(ConsoleEvent e, AppRow? row,
        Func<string, RuleAction> getRule, Action<string, RuleAction> setRule)
    {
        InitializeComponent();
        _event = e;
        _row = row;
        _getRule = getRule;
        _setRule = setRule;

        Time.Text = e.Time.ToString("dddd d 'de' MMMM, HH:mm:ss");
        ShowOutcome();
        FillApp();
        FillRemote();
        UpdateSentence();
    }

    private void ShowOutcome()
    {
        (string text, Color color) = _event.Outcome switch
        {
            "Bloqueado" => ("✖  CONEXIÓN BLOQUEADA", Color.FromRgb(255, 215, 215)),
            "Permitido" => ("✔  CONEXIÓN PERMITIDA", Color.FromRgb(210, 245, 210)),
            "Pregunta" => ("?  ESPERANDO TU RESPUESTA", Color.FromRgb(255, 235, 200)),
            "Oculto" => ("⚠  PROGRAMA OCULTO", Color.FromRgb(255, 235, 200)),
            "Red" => ("ℹ  PROGRAMA USANDO INTERNET", Color.FromRgb(225, 235, 250)),
            "Escaneo" => ("⚠  POSIBLE ATAQUE: ESCANEO DE PUERTOS", Color.FromRgb(255, 200, 200)),
            "Sospechoso" => ("⚠  PROGRAMA SOSPECHOSO", Color.FromRgb(255, 220, 190)),
            _ => ("ℹ  INFORMACIÓN", Color.FromRgb(235, 235, 235))
        };
        Outcome.Text = text;
        Banner.Background = new SolidColorBrush(color);
    }

    // ------------------------------------------------------------------

    private void FillApp()
    {
        string? path = _event.AppPath;
        if (string.IsNullOrEmpty(path))
        {
            AppSection.Visibility = Visibility.Collapsed;
            _appLabel = "Un programa desconocido";
            return;
        }

        var info = FileDetails.Read(path);
        string name = Path.GetFileName(path);
        AppIcon.Source = _row?.Icon ?? ProcessMonitor.LoadIcon(path);
        AppName.Text = name;
        AppDescription.Text = info.Description.Length > 0 ? info.Description : "(el archivo no lo indica)";
        AppCompany.Text = info.Company.Length > 0 ? info.Company : "(el archivo no lo indica)";
        AppSigner.Text = "comprobando...";
        _ = CheckSignatureAsync(path);
        AppVersion.Text = info.Version;
        AppPath.Text = path;

        AppState.Text = _row == null
            ? (_event.Pid > 0 ? $"Ya no se está ejecutando (era el PID {_event.Pid})" : "No se está ejecutando ahora")
            : $"En ejecución (PID {_row.Pid}) · {_row.KindText} · {_row.MemoryText} de memoria";
        if (_row?.Kind == ProcessKind.Oculto)
            AppState.Text += " · ⚠ funciona sin ventana";

        BtnFolder.IsEnabled = File.Exists(path);
        UpdateRule();

        string friendly = info.Description.Length > 0 && !info.Description.Equals(name, StringComparison.OrdinalIgnoreCase)
            ? $"{info.Description} ({name})" : name;
        _appLabel = info.Company.Length > 0 ? $"{friendly}, de {info.Company}," : friendly;
    }

    private async Task CheckSignatureAsync(string path)
    {
        var sig = await Task.Run(() => Signature.CheckNow(path));
        AppSigner.Text = sig.Long;
        AppSigner.Foreground = sig.Status switch
        {
            SignatureStatus.Valida => Brushes.DarkGreen,
            SignatureStatus.NoValida => Brushes.Red,
            SignatureStatus.SinFirma => Brushes.DarkOrange,
            _ => Brushes.Black
        };
    }

    private void UpdateRule()
    {
        if (string.IsNullOrEmpty(_event.AppPath)) return;
        var rule = _getRule(_event.AppPath);
        AppRule.Text = rule switch
        {
            RuleAction.Permitir => "✔ Permitido siempre",
            RuleAction.Bloquear => "✖ Bloqueado siempre",
            _ => "Sin regla (sigue el modo general)"
        };
        AppRule.Foreground = rule switch
        {
            RuleAction.Permitir => Brushes.DarkGreen,
            RuleAction.Bloquear => Brushes.DarkRed,
            _ => Brushes.Black
        };
        BtnAllow.IsEnabled = rule != RuleAction.Permitir;
        BtnBlock.IsEnabled = rule != RuleAction.Bloquear;
        BtnAsk.IsEnabled = rule != RuleAction.Preguntar;
    }

    // ------------------------------------------------------------------

    private void FillRemote()
    {
        var ip = _event.RemoteAddress;
        if (ip == null)
        {
            RemoteSection.Visibility = Visibility.Collapsed;
            return;
        }
        if (_event.Inbound) RemoteTitle.Text = "Quién intentaba entrar en el ordenador";

        RemoteIp.Text = ip.ToString();
        string meaning = Ports.Describe(_event.RemotePort, _event.Protocol);
        RemotePort.Text = _event.RemotePort == 0 ? "" : meaning.Length > 0 ? $"{_event.RemotePort}: {meaning}" : _event.RemotePort.ToString();
        RemoteProtocol.Text = _event.Protocol;

        _ = LookupOwnerAsync(ip);
        _ = LookupNameAsync(ip);
    }

    private async Task LookupOwnerAsync(IPAddress ip)
    {
        var owner = await IpInfo.LookupAsync(ip);
        if (owner.Note.Length > 0)
        {
            RemoteOwner.Text = owner.Note;
            RemoteOwner.FontWeight = FontWeights.Normal;
            return;
        }
        RemoteOwner.Text = owner.Network.Length > 0 && owner.Network != owner.Organization
            ? $"{owner.Organization}   (red: {owner.Network})" : owner.Organization;
        RemoteCountry.Text = owner.Country;
        _ownerLabel = owner.Organization;
        if (owner.Country.Length > 0 && IpInfo.Special(ip) == null) _ownerLabel += $" ({owner.Country})";
        UpdateSentence();
    }

    private async Task LookupNameAsync(IPAddress ip)
    {
        if (IpInfo.Special(ip) != null && !IPAddress.IsLoopback(ip))
        {
            RemoteName.Text = "(aparato de la red de casa)";
        }
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            _serverName = entry.HostName;
            RemoteName.Text = _serverName;
        }
        catch
        {
            RemoteName.Text = "(no tiene nombre público)";
        }
        UpdateSentence();
    }

    // ------------------------------------------------------------------

    /// <summary>Frase resumen para que cualquiera entienda lo que ha pasado.</summary>
    private void UpdateSentence()
    {
        var ip = _event.RemoteAddress;
        if (ip == null)
        {
            Sentence.Text = _event.Text;
            return;
        }

        if (_event.Outcome == "Escaneo")
        {
            string from = _ownerLabel.Length > 0 ? $"{ip} ({_ownerLabel})" : ip.ToString();
            Sentence.Text = $"El equipo {from} ha llamado a muchas puertas distintas de este ordenador en poco tiempo. " +
                            "Eso suele ser alguien buscando una forma de entrar. Las entradas se han bloqueado. " +
                            "Si es un aparato de casa (impresora, consola, otro PC), puede ser normal.";
            return;
        }

        string who = _ownerLabel.Length > 0 ? _ownerLabel : (_serverName.Length > 0 ? _serverName : ip.ToString());
        string what = Ports.Describe(_event.RemotePort, _event.Protocol);
        string forWhat = what.Length > 0 ? $", para {what}" : "";
        string verb = _event.Inbound ? "intentó entrar desde" : "intentó conectarse con";
        string end = _event.Outcome switch
        {
            "Bloqueado" => " Firewall Familiar lo ha bloqueado.",
            "Permitido" => " Se ha permitido.",
            "Pregunta" => " Está esperando a que decidas si se le deja.",
            _ => ""
        };
        Sentence.Text = $"{_appLabel} {verb} {who}{forWhat}.{end}";
    }

    // ------------------------------------------------------------------

    private void SetRule(RuleAction action)
    {
        if (string.IsNullOrEmpty(_event.AppPath)) return;
        _setRule(_event.AppPath, action);
        UpdateRule();
    }

    private void OnAllow(object sender, RoutedEventArgs e) => SetRule(RuleAction.Permitir);
    private void OnBlock(object sender, RoutedEventArgs e) => SetRule(RuleAction.Bloquear);
    private void OnAsk(object sender, RoutedEventArgs e) => SetRule(RuleAction.Preguntar);

    private void OnFolder(object sender, RoutedEventArgs e)
    {
        if (_event.AppPath is { } p && File.Exists(p)) Process.Start("explorer.exe", $"/select,\"{p}\"");
    }

    private void OnSearchApp(object sender, RoutedEventArgs e)
    {
        string file = Path.GetFileName(_event.AppPath ?? "");
        Open("https://www.google.com/search?q=" + Uri.EscapeDataString($"\"{file}\" qué es proceso"));
    }

    private void OnSearchIp(object sender, RoutedEventArgs e)
    {
        if (_event.RemoteAddress != null)
            Open("https://www.google.com/search?q=" + Uri.EscapeDataString(_event.RemoteAddress + " ip propietario"));
    }

    private void OnCopyIp(object sender, RoutedEventArgs e)
    {
        if (_event.RemoteAddress != null) Clipboard.SetText(_event.RemoteAddress.ToString());
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();

    private static void Open(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
}
