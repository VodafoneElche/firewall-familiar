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
            ShowOrphans();
            var live = _startup.Where(i => !i.IsLeftover).ToList();
            int review = live.Count(i => i.Level >= 3);
            int orphans = _startup.Count(i => i.IsLeftover);
            StatusText.Text = $"{live.Count} cosas arrancan solas, {live.Count(i => !i.IsWindows)} no son de Windows. " +
                              (review > 0 ? $"{review} conviene mirarlas (en naranja)." : "Ninguna parece peligrosa.") +
                              (orphans > 0 ? $" Hay {orphans} entradas de programas que ya no existen: están en \"Restos de programas\"." : "");
        }
        catch (Exception ex) { StatusText.Text = "No se pudo revisar el arranque: " + ex.Message; }
        finally { _busy = false; }
    }

    private void ShowStartup()
    {
        bool all = ChkMicrosoft.IsChecked == true;
        StartupList.ItemsSource = _startup.Where(i => !i.IsLeftover && (all || !i.IsWindows || i.Risk != null))
            .OrderByDescending(i => i.Level).ThenBy(i => i.Kind).ThenBy(i => i.Name).ToList();
        ChkAllStartup.IsChecked = false;
        ShowDetail();
    }

    private IEnumerable<StartupItem> ShownStartup => StartupList.ItemsSource as IEnumerable<StartupItem> ?? Enumerable.Empty<StartupItem>();

    /// <summary>Las filas con la casilla marcada o, si no hay ninguna, la fila pinchada.</summary>
    private List<StartupItem> ChosenStartup()
    {
        var marked = ShownStartup.Where(i => i.Selected).ToList();
        if (marked.Count > 0) return marked;
        return StartupList.SelectedItem is StartupItem one ? new() { one } : new();
    }

    private void OnFilterStartup(object sender, RoutedEventArgs e) => ShowStartup();
    private async void OnRefreshStartup(object sender, RoutedEventArgs e) => await LoadStartupAsync();

    private void OnSelectAllStartup(object sender, RoutedEventArgs e)
    {
        bool on = ChkAllStartup.IsChecked == true;
        // "Marcar todos" no marca lo de Windows: eso se marca a mano si de verdad se quiere
        foreach (var i in ShownStartup) i.Selected = on && i.CanMark && !i.IsWindows;
        StartupList.Items.Refresh();
        StatusText.Text = on ? $"Marcadas {ShownStartup.Count(i => i.Selected)}. Desmarca las que quieras dejar como están." : "Desmarcadas todas.";
    }

    private void OnDisable(object sender, RoutedEventArgs e) => Toggle(false);
    private void OnEnable(object sender, RoutedEventArgs e) => Toggle(true);

    private void Toggle(bool enable)
    {
        var chosen = ChosenStartup();
        if (chosen.Count == 0) { StatusText.Text = "Primero marca la casilla de lo que quieras cambiar (o pincha una fila)."; return; }
        var can = chosen.Where(i => i.CanToggle && i.Enabled != enable).ToList();
        if (can.Count == 0)
        {
            if (chosen.Count == 1 && !chosen[0].CanToggle)
                MessageBox.Show(this, chosen[0].IsSetting || chosen[0].Kind == "Secuestro de programa"
                        ? "Esto no se puede desactivar desde aquí. Si no sabes de dónde viene, desinstala el programa que lo puso o pásale el antivirus."
                        : "Esta entrada no se puede desactivar desde aquí (es de una cuenta sin la sesión abierta o de un tipo especial). Prueba con \"Eliminar\".",
                    "Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Information);
            else StatusText.Text = enable ? "Lo marcado ya está activo." : "Lo marcado ya está desactivado.";
            return;
        }
        var windows = can.Where(i => i.IsWindows).ToList();
        if (!enable && windows.Count > 0 &&
            MessageBox.Show(this, $"{string.Join(", ", windows.Select(w => $"\"{w.Name}\""))} es de Microsoft (parte de Windows). Desactivarlo puede hacer que algo de Windows deje de funcionar.\n\n¿Desactivarlo igualmente?",
                "Firewall Familiar", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        if (can.Count > 1 &&
            MessageBox.Show(this, $"¿{(enable ? "Volver a activar" : "Desactivar")} estas {can.Count}?\n\n" + string.Join("\n", can.Take(15).Select(i => $"• {i.Name} ({i.Kind.ToLowerInvariant()})")) +
                    (can.Count > 15 ? $"\n... y {can.Count - 15} más" : "") + (enable ? "" : "\n\nSe puede deshacer con \"Volver a activar\"."),
                "Firewall Familiar", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        int ok = 0;
        var errors = new List<string>();
        foreach (var item in can)
        {
            try
            {
                StartupItems.SetEnabled(item, enable);
                ok++;
                item.Selected = false;
                _log($"Limpieza: {(enable ? "vuelto a activar" : "desactivado")} {item.Kind.ToLowerInvariant()} \"{item.Name}\" ({item.Shown}).");
            }
            catch (Exception ex) { errors.Add($"{item.Name}: {ex.Message}"); }
        }
        bool restart = can.Any(i => i.Kind == "Servicio" || i.Kind == "Menú contextual");
        StatusText.Text = (enable ? $"{ok} vuelven a arrancar solos." : $"{ok} ya no arrancarán solos{(restart ? " (los servicios y menús, desde el próximo reinicio)" : "")}. Se puede volver a activar.") +
                          (errors.Count > 0 ? " No se pudo con: " + string.Join("; ", errors) + (can.Any(i => i.Kind == "Servicio") ? " (algunos antivirus protegen sus servicios)." : "") : "");
        StartupList.Items.Refresh();
        ShowDetail();
    }

    private void OnStartupSelected(object sender, System.Windows.Controls.SelectionChangedEventArgs e) => ShowDetail();

    private void ShowDetail()
    {
        if (StartupList.SelectedItem is not StartupItem i)
        {
            DetailAdvice.Text = "Pincha una línea para ver qué es y qué conviene hacer.";
            DetailInfo.Text = "";
            BtnRemove.IsEnabled = BtnDisable.IsEnabled = BtnEnable.IsEnabled = true;
            return;
        }
        DetailAdvice.Text = (i.Level >= 3 ? "⚠ " : "") + i.Advice;
        DetailInfo.Text = $"{i.Kind}: {i.Name}" + (i.User != "Todos" ? $" (cuenta {i.User})" : "") +
                          (i.Risk != null ? $"\nMotivo: {i.Risk}." : "") +
                          $"\nQué ejecuta: {i.Command}" +
                          (i.IsSetting ? "" : $"\nFirma: {(i.FileMissing ? "el archivo no existe" : i.Signature.Long)}") +
                          $"\nDónde está apuntado: {i.Where}";
        bool marked = ShownStartup.Any(x => x.Selected);
        BtnRemove.IsEnabled = marked || i.CanRemove;
        BtnDisable.IsEnabled = marked || (i.CanToggle && i.Enabled);
        BtnEnable.IsEnabled = marked || (i.CanToggle && !i.Enabled);
    }

    private async void OnRemove(object sender, RoutedEventArgs e)
    {
        var chosen = ChosenStartup();
        if (chosen.Count == 0) { StatusText.Text = "Primero marca la casilla de lo que quieras eliminar (o pincha una fila)."; return; }
        var can = chosen.Where(i => i.CanRemove).ToList();
        if (can.Count == 0) { StatusText.Text = "Esto no se puede eliminar desde aquí (lo de Windows y algunos ajustes no se tocan). Prueba con \"Desactivar\"."; return; }
        string names = string.Join("\n", can.Take(15).Select(i => $"• {i.Name} ({i.Kind.ToLowerInvariant()})")) + (can.Count > 15 ? $"\n... y {can.Count - 15} más" : "");
        if (MessageBox.Show(this, $"¿Eliminar para siempre {(can.Count == 1 ? "esta entrada" : $"estas {can.Count} entradas")}?\n\n{names}\n\n" +
                "OJO: el programa sigue instalado; solo deja de arrancar solo. Si lo usas, mejor \"Desactivar\" (se puede deshacer).\n\n" +
                "Antes se guarda una copia en C:\\ProgramData\\FirewallFamiliar\\copias-limpieza (con doble clic en el .reg se vuelve a poner).",
                "Firewall Familiar", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        var (ok, errors) = await RemoveEntries(can);
        ShowStartup();
        StatusText.Text = $"{ok} entradas eliminadas (copia en C:\\ProgramData\\FirewallFamiliar\\copias-limpieza)." + (errors.Count > 0 ? " No se pudo con: " + string.Join("; ", errors) : "");
    }

    private async Task<(int ok, List<string> errors)> RemoveEntries(List<StartupItem> items)
    {
        int ok = 0;
        var errors = new List<string>();
        foreach (var item in items)
        {
            try
            {
                string backup = await Task.Run(() => StartupItems.Remove(item));
                _log($"Limpieza: eliminada la entrada {item.Kind.ToLowerInvariant()} \"{item.Name}\" ({item.Shown}). Copia en {backup}.");
                _startup.Remove(item);
                ok++;
            }
            catch (Exception ex) { errors.Add($"{item.Name}: {ex.Message}"); }
        }
        return (ok, errors);
    }

    private void OnOpenStartupFile(object sender, RoutedEventArgs e) =>
        OpenLocation(StartupList.SelectedItem as StartupItem ?? ChosenStartup().FirstOrDefault());

    private void OpenLocation(StartupItem? item)
    {
        if (item == null) { StatusText.Text = "Primero pincha una fila de la lista."; return; }
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

    // ------------------------------------------------------------------ Entradas huérfanas (programas que ya no existen)
    private void ShowOrphans()
    {
        OrphanList.ItemsSource = _startup.Where(i => i.IsLeftover).OrderBy(i => i.Kind).ThenBy(i => i.Name).ToList();
        ChkAllOrphans.IsChecked = false;
    }

    private IEnumerable<StartupItem> ShownOrphans => OrphanList.ItemsSource as IEnumerable<StartupItem> ?? Enumerable.Empty<StartupItem>();

    private void OnSelectAllOrphans(object sender, RoutedEventArgs e)
    {
        bool on = ChkAllOrphans.IsChecked == true;
        foreach (var i in ShownOrphans) i.Selected = on && i.CanRemove;
        OrphanList.Items.Refresh();
        StatusText.Text = on ? $"Marcadas {ShownOrphans.Count(i => i.Selected)} entradas." : "Desmarcadas todas.";
    }

    private void OnOpenOrphan(object sender, RoutedEventArgs e) => OpenLocation(OrphanList.SelectedItem as StartupItem);

    private async void OnRemoveOrphans(object sender, RoutedEventArgs e)
    {
        var chosen = ShownOrphans.Where(i => i.Selected && i.CanRemove).ToList();
        if (chosen.Count == 0 && OrphanList.SelectedItem is StartupItem one && one.CanRemove) chosen.Add(one);
        if (chosen.Count == 0) { StatusText.Text = "Marca primero en la columna \"Quitar\" las entradas que quieras eliminar."; return; }
        string names = string.Join("\n", chosen.Take(15).Select(i => $"• {i.Name} ({i.Kind.ToLowerInvariant()})")) + (chosen.Count > 15 ? $"\n... y {chosen.Count - 15} más" : "");
        if (MessageBox.Show(this, $"¿Eliminar {(chosen.Count == 1 ? "esta entrada" : $"estas {chosen.Count} entradas")}?\n\n{names}\n\n" +
                "Son restos: el programa ya no está, así que no se pierde nada. Antes se guarda una copia en C:\\ProgramData\\FirewallFamiliar\\copias-limpieza.",
                "Firewall Familiar", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        var (ok, errors) = await RemoveEntries(chosen);
        ShowOrphans();
        StatusText.Text = $"{ok} entradas eliminadas." + (errors.Count > 0 ? " No se pudo con: " + string.Join("; ", errors) : "");
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
