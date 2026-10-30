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
            StatusText.Text = $"{_startup.Count} cosas arrancan solas, {_startup.Count(i => !i.IsWindows)} no son de Windows. " +
                              (review > 0 ? $"{review} conviene mirarlas (en naranja)." : "Ninguna parece peligrosa.") +
                              (_startup.Count(i => i.FileMissing && i.CanRemove) is int rests and > 0 ? $" {rests} son restos que se pueden eliminar." : "");
        }
        catch (Exception ex) { StatusText.Text = "No se pudo revisar el arranque: " + ex.Message; }
        finally { _busy = false; }
    }

    private void ShowStartup()
    {
        bool all = ChkMicrosoft.IsChecked == true;
        StartupList.ItemsSource = _startup.Where(i => all || !i.IsWindows || (i.Risk != null && !i.FileMissing))
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
        if (!enable && item.IsWindows &&
            MessageBox.Show(this, $"\"{item.Name}\" es de Microsoft (parte de Windows). Desactivarlo puede hacer que algo de Windows deje de funcionar.\n\n¿Desactivarlo igualmente?",
                "Firewall Familiar", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            StartupItems.SetEnabled(item, enable);
            _log($"Limpieza: {(enable ? "vuelto a activar" : "desactivado")} {item.Kind.ToLowerInvariant()} \"{item.Name}\" ({item.Shown}).");
            StatusText.Text = enable ? $"\"{item.Name}\" vuelve a arrancar solo." :
                $"\"{item.Name}\" ya no arrancará solo{(item.Kind == "Servicio" || item.Kind == "Menú contextual" ? " (desde el próximo reinicio)" : "")}. Se puede volver a activar.";
            StartupList.Items.Refresh();
            ShowDetail();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "No se pudo cambiar: " + ex.Message + (item.Kind == "Servicio" ? "\n\nAlgunos antivirus protegen sus servicios para que no se puedan parar." : ""),
                "Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnStartupSelected(object sender, System.Windows.Controls.SelectionChangedEventArgs e) => ShowDetail();

    private void ShowDetail()
    {
        if (StartupList.SelectedItem is not StartupItem i)
        {
            DetailAdvice.Text = "Pincha una línea para ver qué es y qué conviene hacer.";
            DetailInfo.Text = "";
            return;
        }
        DetailAdvice.Text = (i.Level >= 3 ? "⚠ " : "") + i.Advice;
        DetailInfo.Text = $"{i.Kind}: {i.Name}" + (i.User != "Todos" ? $" (cuenta {i.User})" : "") +
                          (i.Risk != null ? $"\nMotivo: {i.Risk}." : "") +
                          $"\nQué ejecuta: {i.Command}" +
                          (i.IsSetting ? "" : $"\nFirma: {(i.FileMissing ? "el archivo no existe" : i.Signature.Long)}") +
                          $"\nDónde está apuntado: {i.Where}";
        BtnRemove.IsEnabled = i.CanRemove;
        BtnDisable.IsEnabled = i.CanToggle && i.Enabled;
        BtnEnable.IsEnabled = i.CanToggle && !i.Enabled;
    }

    private async void OnRemove(object sender, RoutedEventArgs e)
    {
        if (StartupList.SelectedItem is not StartupItem item) { StatusText.Text = "Primero elige una fila de la lista."; return; }
        if (!item.CanRemove) { StatusText.Text = "Esta entrada no se puede eliminar desde aquí."; return; }
        string warn = item.FileMissing ? "Es un resto: el programa ya no está, así que no se pierde nada."
            : "OJO: el programa sigue instalado. Si lo usas, mejor \"Desactivar\" (se puede deshacer).";
        if (MessageBox.Show(this, $"¿Eliminar la entrada \"{item.Name}\" ({item.Kind.ToLowerInvariant()})?\n\n{warn}\n\n" +
                "Antes se guarda una copia en C:\\ProgramData\\FirewallFamiliar\\copias-limpieza (con doble clic en el .reg se vuelve a poner).",
                "Firewall Familiar", MessageBoxButton.YesNo, item.FileMissing ? MessageBoxImage.Question : MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            string backup = await System.Threading.Tasks.Task.Run(() => StartupItems.Remove(item));
            _log($"Limpieza: eliminada la entrada {item.Kind.ToLowerInvariant()} \"{item.Name}\" ({item.Shown}). Copia en {backup}.");
            _startup.Remove(item);
            ShowStartup();
            StatusText.Text = $"Eliminada \"{item.Name}\". Copia guardada en {backup}.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "No se pudo eliminar: " + ex.Message, "Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnOpenStartupFile(object sender, RoutedEventArgs e)
    {
        if (StartupList.SelectedItem is not StartupItem item) { StatusText.Text = "Primero elige una fila de la lista."; return; }
        try
        {
            if (item.Path.Length > 0 && File.Exists(item.Path)) { Process.Start("explorer.exe", $"/select,\"{item.Path}\""); return; }
            // El archivo ya no existe: se abre donde está apuntada la entrada
            if (item.Kind == "Tarea programada") { Process.Start(new ProcessStartInfo("taskschd.msc") { UseShellExecute = true }); StatusText.Text = $"Abierto el Programador de tareas: busca \"{item.Name}\"."; return; }
            if (item.RegKey != null) { StartupItems.OpenInRegedit(item.RegKey); StatusText.Text = $"Abierto el Editor del registro en {item.RegKey} (valor \"{item.Name}\")."; return; }
            if (item.Kind == "Carpeta Inicio" && Directory.Exists(item.Where)) { Process.Start("explorer.exe", $"\"{item.Where}\""); return; }
            string? dir = item.Path.Length > 0 ? Path.GetDirectoryName(item.Path) : null;
            if (dir != null && Directory.Exists(dir)) Process.Start("explorer.exe", $"\"{dir}\"");
            else StatusText.Text = "El archivo ya no existe y no hay ninguna carpeta que abrir.";
        }
        catch (Exception ex) { StatusText.Text = "No se pudo abrir: " + ex.Message; }
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
            ChkAll.IsChecked = false;
            if (Tabs.SelectedIndex == 1 || before.Length == 0)
                StatusText.Text = _leftovers.Count == 0 ? "No hay restos de programas." :
                    $"{_leftovers.Count} carpetas parecen restos ({Models.Format.Bytes(_leftovers.Sum(l => l.Size))}). Revísalas antes de quitarlas.";
        }
        catch (Exception ex) { StatusText.Text = "No se pudo buscar restos: " + ex.Message; }
        finally { BtnRecycle.IsEnabled = true; }
    }

    private void OnSelectAll(object sender, RoutedEventArgs e)
    {
        bool on = ChkAll.IsChecked == true;
        foreach (var l in _leftovers) l.Selected = on && l.CanSelect;
        LeftoverList.Items.Refresh();
        StatusText.Text = on ? $"Marcadas {_leftovers.Count(l => l.Selected)} carpetas. Desmarca las que quieras conservar." : "Desmarcadas todas.";
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
