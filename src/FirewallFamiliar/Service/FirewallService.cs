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
        CanHandlePowerEvent = true;
        AutoLog = false;
    }

    protected override void OnStart(string[] args) => _core.Start();

    protected override void OnStop() => _core.Stop();

    protected override void OnShutdown() => _core.Stop(shutdown: true);

    protected override bool OnPowerEvent(PowerBroadcastStatus status)
    {
        if (status == PowerBroadcastStatus.Suspend) _core.OnSuspend();
        else if (status is PowerBroadcastStatus.ResumeSuspend or PowerBroadcastStatus.ResumeAutomatic) _core.OnResume();
        return true;
    }

    protected override void OnSessionChange(SessionChangeDescription change)
    {
        if (change.Reason is SessionChangeReason.SessionLogon or SessionChangeReason.SessionUnlock or SessionChangeReason.ConsoleConnect)
            _core.OnLogon(change.SessionId);
    }
}
