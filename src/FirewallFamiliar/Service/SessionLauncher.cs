using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace FirewallFamiliar.Service;

/// <summary>
/// El servicio corre aparte, sin escritorio. Para que cada usuario vea el icono junto al reloj,
/// el servicio abre "FirewallFamiliar.exe --icono" en la sesión de ese usuario y con su cuenta
/// (no con la del sistema), igual que si lo hubiera abierto él.
/// </summary>
internal static class SessionLauncher
{
    /// <summary>Abre el icono en todas las sesiones con usuario que aún no lo tengan.</summary>
    public static void LaunchInAllSessions(string exe, Action<string> log)
    {
        foreach (int session in ActiveSessions())
            LaunchInSession(session, exe, log);
    }

    public static void LaunchInSession(int session, string exe, Action<string> log)
    {
        if (session <= 0 || HasOurProcess(session)) return;
        IntPtr token = IntPtr.Zero, env = IntPtr.Zero;
        try
        {
            if (!WTSQueryUserToken((uint)session, out token)) return; // sesión sin usuario (pantalla de inicio)
            CreateEnvironmentBlock(out env, token, false);
            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            string cmd = $"\"{exe}\" --icono";
            string? dir = System.IO.Path.GetDirectoryName(exe);
            if (CreateProcessAsUser(token, null, cmd, IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, env, dir, ref si, out var pi))
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            else log($"No se pudo abrir el icono en la sesión {session} (error {Marshal.GetLastWin32Error()}).");
        }
        catch (Exception ex) { log("No se pudo abrir el icono: " + ex.Message); }
        finally
        {
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    /// <summary>¿Ya hay un Firewall Familiar (icono o ventana) en esa sesión?</summary>
    private static bool HasOurProcess(int session)
    {
        int self = Environment.ProcessId;
        foreach (var p in Process.GetProcessesByName("FirewallFamiliar"))
            using (p)
            {
                try { if (p.Id != self && p.SessionId == session) return true; } catch { }
            }
        return false;
    }

    private static int[] ActiveSessions()
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buffer, out int count)) return Array.Empty<int>();
            int size = Marshal.SizeOf<WTS_SESSION_INFO>();
            return Enumerable.Range(0, count)
                .Select(i => Marshal.PtrToStructure<WTS_SESSION_INFO>(buffer + i * size))
                .Where(s => s.State == WTS_ACTIVE || s.State == WTS_DISCONNECTED)
                .Select(s => s.SessionId)
                .ToArray();
        }
        catch { return Array.Empty<int>(); }
        finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
    }

    private const int WTS_ACTIVE = 0, WTS_DISCONNECTED = 4;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x400, CREATE_NO_WINDOW = 0x08000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr env);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(IntPtr token, string? app, string cmd, IntPtr procAttr, IntPtr threadAttr,
        bool inherit, uint flags, IntPtr env, string? dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
