using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using FirewallFamiliar.Core;

namespace FirewallFamiliar.Views;

/// <summary>
/// Limpieza y revisión del PC: lo que arranca solo (con su firma), restos de programas
/// desinstalados, salud de los discos y chequeo de seguridad. Nada se conecta a Internet,
/// nada se borra sin enseñarlo antes, y lo borrado va a la Papelera.
/// </summary>
public partial class CleanupWindow : Window
{
    private readonly Action<string> _log;
    private List<StartupItem> _startup = new();
    private List<LeftoverFolder> _leftovers = new();
    private bool _busy;

    public CleanupWindow(Action<string> log)
    {
        InitializeComponent();
        _log = log;
        Loaded += async (_, _) =>
        {
            await LoadStartupAsync();
            await LoadHealthAsync();
            await LoadLeftoversAsync();
        };
    }

    // ------------------------------------------------------------------ Arranque
    private async Task LoadStartupAsync()
    {
        if (_busy) return;
        _busy = true;
        StatusText.Text = "Revisando lo que arranca solo y comprobando las firmas digitales (tarda unos segundos)...";
        try
        {
            _startup = await Task.Run(() => StartupItems.Collect());
            ShowStartup();
            int review = _startup.Count(i => i.Level >= 3);
            StatusText.Text = $"{_startup.Count} cosas arrancan solas, {_startup.Count(i => !i.IsMicrosoft)} no son de Microsoft. " +
                              (review > 0 ? $"{review} conviene mirarlas (en naranja)." : "Ninguna parece peligrosa.");
        }
        catch (Exception ex) { StatusText.Text = "No se pudo revisar el arranque: " + ex.Message; }
        finally { _busy = false; }
    }

    private void ShowStartup()
    {
        bool all = ChkMicrosoft.IsChecked == true;
        StartupList.ItemsSource = _startup.Where(i => all || !i.IsMicrosoft || i.Risk != null)
            .OrderByDescending(i => i.Level).ThenBy(i => i.Kind).ThenBy(i => i.Name).ToList();
    }

    private void OnFilterStartup(object sender, RoutedEventArgs e) => ShowStartup();
    private async void OnRefreshStartup(object sender, RoutedEventArgs e) => await LoadStartupAsync();

    private void OnDisable(object sender, RoutedEventArgs e) => Toggle(false);
    private void OnEnable(object sender, RoutedEventArgs e) => Toggle(true);

    private void Toggle(bool enable)
    {
        if (StartupList.SelectedItem is not StartupItem item) { StatusText.Text = "Primero elige una fila de la lista."; return; }
        if (!item.CanToggle)
        {
            MessageBox.Show(this, item.IsSetting || item.Kind == "Secuestro de programa"
                    ? "Esto no se puede desactivar desde aquí. Si no sabes de dónde viene, desinstala el programa que lo puso o pásale el antivirus."
                    : "Esta entrada no se puede desactivar desde aquí (es de una cuenta sin la sesión abierta o de un tipo especial).",
                "Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (item.Enabled == enable) { StatusText.Text = enable ? "Ya está activo." : "Ya está desactivado."; return; }
        if (!enable && item.IsMicrosoft &&
            MessageBox.Show(this, $"\"{item.Name}\" es de Microsoft (parte de Windows). Desactivarlo puede hacer que algo de Windows deje de funcionar.\n\n¿Desactivarlo igualmente?",
                "Firewall Familiar", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            StartupItems.SetEnabled(item, enable);
            _log($"Limpieza: {(enable ? "vuelto a activar" : "desactivado")} {item.Kind.ToLowerInvariant()} \"{item.Name}\" ({item.Shown}).");
            StatusText.Text = enable ? $"\"{item.Name}\" vuelve a arrancar solo." :
                $"\"{item.Name}\" ya no arrancará solo{(item.Kind == "Servicio" || item.Kind == "Menú contextual" ? " (desde el próximo reinicio)" : "")}. Se puede volver a activar.";
            StartupList.Items.Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "No se pudo cambiar: " + ex.Message + (item.Kind == "Servicio" ? "\n\nAlgunos antivirus protegen sus servicios para que no se puedan parar." : ""),
                "Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnOpenStartupFile(object sender, RoutedEventArgs e)
    {
        if (StartupList.SelectedItem is not StartupItem item) return;
        if (item.Path.Length > 0 && File.Exists(item.Path)) Process.Start("explorer.exe", $"/select,\"{item.Path}\"");
        else if (item.Path.Length > 0 && Directory.Exists(Path.GetDirectoryName(item.Path))) Process.Start("explorer.exe", $"\"{Path.GetDirectoryName(item.Path)}\"");
        else StatusText.Text = "El archivo ya no existe.";
    }

    // ------------------------------------------------------------------ Restos
    private async Task LoadLeftoversAsync()
    {
        string before = StatusText.Text;
        LeftoverList.ItemsSource = null;
        BtnRecycle.IsEnabled = false;
        try
        {
            var inUse = _startup.Where(i => i.Enabled).Select(i => i.Path).ToList();
            _leftovers = await Task.Run(() => Leftovers.Find(inUse));
            LeftoverList.ItemsSource = _leftovers;
            if (Tabs.SelectedIndex == 1 || before.Length == 0)
                StatusText.Text = _leftovers.Count == 0 ? "No hay restos de programas." :
                    $"{_leftovers.Count} carpetas parecen restos ({Models.Format.Bytes(_leftovers.Sum(l => l.Size))}). Revísalas antes de quitarlas.";
        }
        catch (Exception ex) { StatusText.Text = "No se pudo buscar restos: " + ex.Message; }
        finally { BtnRecycle.IsEnabled = true; }
    }

    private async void OnRefreshLeftovers(object sender, RoutedEventArgs e) => await LoadLeftoversAsync();

    private void OnOpenLeftover(object sender, RoutedEventArgs e)
    {
        if (LeftoverList.SelectedItem is LeftoverFolder f && Directory.Exists(f.Path)) Process.Start("explorer.exe", $"\"{f.Path}\"");
    }

    private async void OnRecycle(object sender, RoutedEventArgs e)
    {
        var chosen = _leftovers.Where(l => l.Selected && !l.InUse).ToList();
        if (chosen.Count == 0) { StatusText.Text = "Marca primero en la columna \"Quitar\" las carpetas que quieras quitar."; return; }
        string list = string.Join("\n", chosen.Take(15).Select(c => $"• {c.Path} ({c.SizeText})")) + (chosen.Count > 15 ? $"\n... y {chosen.Count - 15} más" : "");
        if (MessageBox.Show(this, $"Se van a mandar a la Papelera estas {chosen.Count} carpetas:\n\n{list}\n\nSe pueden recuperar desde la Papelera. ¿Seguir?",
                "Firewall Familiar", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        int ok = 0;
        var errors = new List<string>();
        foreach (var c in chosen)
        {
            try
            {
                await Task.Run(() => Leftovers.ToRecycleBin(c));
                ok++;
                _log($"Limpieza: carpeta enviada a la Papelera: {c.Path} ({c.SizeText}).");
            }
            catch (Exception ex) { errors.Add($"{c.Name}: {ex.Message}"); }
        }
        await LoadLeftoversAsync();
        StatusText.Text = $"{ok} carpetas enviadas a la Papelera." + (errors.Count > 0 ? " No se pudieron quitar: " + string.Join("; ", errors) : "");
    }

    // ------------------------------------------------------------------ Discos y chequeo
    private async Task LoadHealthAsync()
    {
        try
        {
            var (disks, volumes, checks) = await Task.Run(() =>
            {
                List<DiskStatus> d;
                try { d = DiskHealth.Check(); } catch { d = new(); }
                return (d, DiskHealth.Volumes(), SecurityCheck.Run());
            });
            DiskList.ItemsSource = disks;
            VolumeList.ItemsSource = volumes;
            CheckList.ItemsSource = checks;
        }
        catch (Exception ex) { StatusText.Text = "No se pudo revisar los discos: " + ex.Message; }
    }

    private async void OnRefreshHealth(object sender, RoutedEventArgs e) => await LoadHealthAsync();
}
