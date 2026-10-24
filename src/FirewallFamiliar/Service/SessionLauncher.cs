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

    /// <summary>
    /// Abre la ventana completa, ya como administrador, en la sesión de un usuario que ES administrador.
    /// Así no sale el aviso de Windows (UAC). Si el usuario de esa sesión es una cuenta estándar
    /// (por ejemplo la de los niños) no se abre y devuelve el motivo: entonces Windows pide la contraseña.
    /// </summary>
    public static string? LaunchElevated(int session, string exe)
    {
        if (session <= 0) return "Sesión no válida.";
        IntPtr token = IntPtr.Zero, full = IntPtr.Zero, env = IntPtr.Zero;
        try
        {
            if (!WTSQueryUserToken((uint)session, out token)) return "No hay usuario en esa sesión.";
            GetTokenInformation(token, TokenElevationType, out int type, 4, out _);
            if (type == 3) // limitado: es administrador con UAC, se usa su token completo
            {
                if (!GetTokenInformation(token, TokenLinkedToken, out full, IntPtr.Size, out _) || full == IntPtr.Zero)
                    return $"No se pudo obtener el permiso de administrador (error {Marshal.GetLastWin32Error()}).";
            }
            else
            {
                // Sin UAC: solo vale si de verdad es administrador
                using var id = new System.Security.Principal.WindowsIdentity(token);
                if (!new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                    return "El usuario no es administrador.";
                DuplicateHandleToken(token, out full);
            }
            CreateEnvironmentBlock(out env, full, false);
            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            string? dir = System.IO.Path.GetDirectoryName(exe);
            if (!CreateProcessAsUser(full, null, $"\"{exe}\"", IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_UNICODE_ENVIRONMENT, env, dir, ref si, out var pi))
                return $"No se pudo abrir la ventana (error {Marshal.GetLastWin32Error()}).";
            AllowSetForegroundWindow(pi.dwProcessId);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return null;
        }
        catch (Exception ex) { return ex.Message; }
        finally
        {
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
            if (full != IntPtr.Zero && full != token) CloseHandle(full);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    private static void DuplicateHandleToken(IntPtr token, out IntPtr copy)
    {
        if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, IntPtr.Zero, 2 /* Impersonation */, 1 /* Primary */, out copy))
            copy = IntPtr.Zero;
    }

    private const int TokenElevationType = 18, TokenLinkedToken = 19;
    private const uint MAXIMUM_ALLOWED = 0x02000000;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int info, int length, out int returned);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out IntPtr info, int length, out int returned);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int type, out IntPtr newToken);

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(int processId);

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
