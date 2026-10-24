using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading.Tasks;

namespace FirewallFamiliar.Core;

/// <summary>
/// Abrir la ventana completa (necesita administrador). Primero se le pide al servicio, que la abre
/// sin el aviso de Windows si el usuario es administrador. Si no (cuenta estándar o servicio parado),
/// Windows pide permiso como siempre.
/// </summary>
public static class FullWindow
{
    /// <summary>Devuelve false si el usuario canceló el permiso de Windows.</summary>
    public static bool Open()
    {
        if (Task.Run(AskServiceAsync).GetAwaiter().GetResult()) return true;
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
            return true;
        }
        catch (Win32Exception) { return false; }
    }

    private static async Task<bool> AskServiceAsync()
    {
        try
        {
            using var ch = await PipeChannel.ConnectAsync(2000);
            if (ch == null) return false;
            await ch.SendAsync(new PipeMessage { T = "abrir-ventana" });
            var deadline = DateTime.Now.AddSeconds(6);
            while (DateTime.Now < deadline)
            {
                var read = ch.ReadAsync();
                if (await Task.WhenAny(read, Task.Delay(deadline - DateTime.Now)) != read) return false;
                var m = await read;
                if (m == null) return false;
                if (m.T == "ventana") return m.Ok;
            }
        }
        catch { }
        return false;
    }
}
