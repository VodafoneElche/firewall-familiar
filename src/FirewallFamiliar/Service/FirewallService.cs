using System.ServiceProcess;

namespace FirewallFamiliar.Service;

/// <summary>El servicio de Windows "Firewall Familiar" (FirewallFamiliar.exe --servicio).</summary>
internal sealed class FirewallService : ServiceBase
{
    private readonly ServiceCore _core = new();

    public FirewallService()
    {
        ServiceName = Core.ServiceSetup.ServiceName;
        CanStop = true;
        CanShutdown = true;
        CanHandleSessionChangeEvent = true;
        AutoLog = false;
    }

    protected override void OnStart(string[] args) => _core.Start();

    protected override void OnStop() => _core.Stop();

    protected override void OnShutdown() => _core.Stop();

    protected override void OnSessionChange(SessionChangeDescription change)
    {
        if (change.Reason is SessionChangeReason.SessionLogon or SessionChangeReason.SessionUnlock or SessionChangeReason.ConsoleConnect)
            _core.OnLogon(change.SessionId);
    }
}
