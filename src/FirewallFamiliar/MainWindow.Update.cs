using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using FirewallFamiliar.Core;

namespace FirewallFamiliar;

/// <summary>Parte de la ventana principal que busca e instala versiones nuevas.</summary>
public partial class MainWindow
{
    private DispatcherTimer? _updateTimer;
    private bool _updating;

    private void InitUpdates()
    {
        // Primera comprobación a los 2 minutos de arrancar; después, cada 6 horas
        _updateTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(2) };
        _updateTimer.Tick += async (_, _) =>
        {
            _updateTimer.Interval = TimeSpan.FromHours(6);
            if (_settings.AutoUpdate) await CheckUpdatesAsync(manual: false);
        };
        _updateTimer.Start();
    }

    private async void OnCheckUpdates(object sender, RoutedEventArgs e) => await CheckUpdatesAsync(manual: true);

    private async Task CheckUpdatesAsync(bool manual)
    {
        if (_updating) return;
        _updating = true;
        try
        {
            UpdateInfo? info;
            try { info = await Updater.CheckAsync(); }
            catch (Exception ex)
            {
                if (manual)
                    MessageBox.Show(this, "No se pudo comprobar si hay versiones nuevas:\n" + ex.Message,
                        "Actualizaciones", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (info == null)
            {
                if (manual)
                    MessageBox.Show(this, $"Tienes la última versión ({Updater.Current.ToString(3)}).",
                        "Actualizaciones", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string v = info.Version.ToString(3);
            if (manual)
            {
                string notes = info.Notes.Length > 600 ? info.Notes[..600] + "..." : info.Notes;
                if (MessageBox.Show(this,
                        $"Hay una versión nueva: {v} (tienes la {Updater.Current.ToString(3)}).\n\n{notes}\n\n" +
                        "¿Instalarla ahora? Firewall Familiar se cerrará unos segundos y se volverá a abrir solo.",
                        "Actualizaciones", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                    return;
            }
            else if (!Updater.InstalledWithSetup)
            {
                // Copia suelta (sin instalar): solo se avisa
                Log($"Hay una versión nueva de Firewall Familiar ({v}). Menú Ayuda → Buscar actualizaciones para instalarla.");
                return;
            }

            Log($"Descargando la versión {v}...");
            string file = await Updater.DownloadAsync(info);
            Log($"Instalando la versión {v}. Firewall Familiar se volverá a abrir en unos segundos.");
            _tray?.Alert("Actualizando Firewall Familiar", $"Instalando la versión {v}. Vuelve en unos segundos.", false);
            await Task.Delay(1500);
            Updater.RunInstaller(file);
            _reallyExit = true;
            Close();
        }
        catch (Exception ex)
        {
            Log("⚠ No se pudo actualizar: " + ex.Message);
            if (manual) MessageBox.Show(this, "No se pudo actualizar: " + ex.Message, "Actualizaciones", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _updating = false;
        }
    }
}
