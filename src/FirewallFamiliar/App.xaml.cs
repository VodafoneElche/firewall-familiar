using System.Windows;
using System.Windows.Threading;

namespace FirewallFamiliar;

public partial class App : Application
{
    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Mostrar el error en lugar de cerrar la aplicación sin avisar.
        MessageBox.Show("Se ha producido un error inesperado:\n\n" + e.Exception.Message,
            "Firewall Familiar", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
