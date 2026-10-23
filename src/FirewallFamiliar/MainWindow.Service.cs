using System;
using System.Threading.Tasks;
using FirewallFamiliar.Core;

namespace FirewallFamiliar;

/// <summary>
/// Relevo con el servicio de Windows: mientras esta ventana está abierta, es ella la que bloquea
/// (con todos los detalles a la vista). Al cerrarla, el servicio vuelve a encargarse solo.
/// </summary>
public partial class MainWindow
{
    private PipeChannel? _serviceLink;

    /// <summary>Hay servicio instalado: cerrar la ventana no deja el PC sin protección.</summary>
    private bool ServiceProtects => _serviceLink != null || ServiceSetup.IsInstalled;

    private async Task TakeOverFromServiceAsync()
    {
        if (!ServiceSetup.IsInstalled) return;
        if (!ServiceSetup.IsRunning) await Task.Run(ServiceSetup.Start);
        var ch = await PipeChannel.ConnectAsync(5000);
        if (ch == null)
        {
            Log("⚠ El servicio de Firewall Familiar no responde. Esta ventana bloquea por su cuenta.");
            return;
        }
        await ch.SendAsync(new PipeMessage { T = "pausa" });
        var deadline = DateTime.Now.AddSeconds(8);
        while (DateTime.Now < deadline)
        {
            var read = ch.ReadAsync();
            if (await Task.WhenAny(read, Task.Delay(deadline - DateTime.Now)) != read) break;
            var m = await read;
            if (m == null) break;
            if (m.T != "pausado") continue;
            if (!m.Ok)
            {
                Log("⚠ El servicio no ha cedido el control: " + m.Error);
                ch.Dispose();
                return;
            }
            _serviceLink = ch;
            Log("El servicio de Firewall Familiar sigue instalado: al cerrar esta ventana, él vuelve a proteger.");
            _ = DrainServiceAsync(ch);
            return;
        }
        Log("⚠ El servicio no ha contestado a tiempo. Esta ventana bloquea por su cuenta.");
        ch.Dispose();
    }

    /// <summary>Se leen (y se ignoran) los mensajes del servicio para que la tubería no se llene.</summary>
    private static async Task DrainServiceAsync(PipeChannel ch)
    {
        while (await ch.ReadAsync() != null) { }
    }

    /// <summary>Al cerrar: se cierra la conexión y el servicio retoma el bloqueo.</summary>
    private void ReturnToService()
    {
        _serviceLink?.Dispose();
        _serviceLink = null;
    }
}
