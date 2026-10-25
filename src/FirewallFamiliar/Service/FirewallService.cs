using System;
using System.Runtime.InteropServices;
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

    // Pantalla encendida/apagada y tapa del portátil. En los portátiles modernos ("espera moderna")
    // cerrar la tapa no avisa de suspensión: solo se apaga la pantalla y luego se corta la red.
    private static Guid _displayState = new("6FE69556-704A-47A0-8F24-C28D936FDA47");
    private static Guid _lidSwitch = new("BA3E0F4D-B817-4094-A2D1-D56379E6A0F3");
    private const int PBT_POWERSETTINGCHANGE = 0x8013;

    protected override void OnStart(string[] args)
    {
        _core.Start();
        try
        {
            RegisterPowerSettingNotification(ServiceHandle, ref _displayState, 1 /* DEVICE_NOTIFY_SERVICE_HANDLE */);
            RegisterPowerSettingNotification(ServiceHandle, ref _lidSwitch, 1);
        }
        catch { }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr RegisterPowerSettingNotification(IntPtr recipient, ref Guid powerSetting, int flags);

    protected override void OnStop() => _core.Stop();

    protected override void OnShutdown() => _core.Stop(shutdown: true);

    protected override bool OnPowerEvent(PowerBroadcastStatus status)
    {
        if ((int)status == PBT_POWERSETTINGCHANGE) _core.OnScreenOrLid();
        else if (status == PowerBroadcastStatus.Suspend) _core.OnSuspend();
        else if (status is PowerBroadcastStatus.ResumeSuspend or PowerBroadcastStatus.ResumeAutomatic) _core.OnResume();
        return true;
    }

    protected override void OnSessionChange(SessionChangeDescription change)
    {
        if (change.Reason is SessionChangeReason.SessionLogon or SessionChangeReason.SessionUnlock or SessionChangeReason.ConsoleConnect)
            _core.OnLogon(change.SessionId);
    }
}
