using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

namespace FirewallFamiliar.Core;

/// <summary>Resultado de una comprobación del chequeo de seguridad.</summary>
public sealed record SecurityFinding(string Key, string Name, bool Ok, string Text)
{
    public string StateText => Ok ? "✔ Bien" : "⚠ Revisar";
}

/// <summary>
/// Chequeo de seguridad de Windows: lo que algunos virus desactivan para quedarse en el PC
/// (Firewall de Windows, antivirus, actualizaciones, Administrador de tareas, control de cuentas)
/// y lo que abre la puerta desde fuera (Escritorio remoto). Solo lee el registro y el Centro de seguridad.
/// </summary>
public static class SecurityCheck
{
    public static List<SecurityFinding> Run()
    {
        var list = new List<SecurityFinding>();
        void Try(Action a) { try { a(); } catch { } }
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

        // Firewall de Windows (Firewall Familiar usa sus avisos para detectar ataques; tiene que estar encendido)
        Try(() =>
        {
            foreach (var (key, name) in new[] { ("StandardProfile", "privada"), ("PublicProfile", "pública"), ("DomainProfile", "de dominio") })
            {
                using var k = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + key);
                using var pol = hklm.OpenSubKey(@"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + key);
                object? v = pol?.GetValue("EnableFirewall") ?? k?.GetValue("EnableFirewall");
                if (v == null) continue;
                bool on = Convert.ToInt32(v) != 0;
                if (key == "DomainProfile" && on) continue; // en casa no se usa; solo se dice si está apagado
                list.Add(new SecurityFinding("fw-" + key, $"Firewall de Windows (red {name})", on,
                    on ? "Encendido." : "APAGADO. Firewall Familiar lo necesita encendido para ver los ataques desde fuera."));
            }
        });

        // Antivirus
        Try(() =>
        {
            var av = AntivirusInfo.ProductList();
            bool ok = av.Any(a => a.On);
            string text = av.Count == 0 ? "Windows no tiene ningún antivirus registrado."
                : string.Join("; ", av.Select(a => $"{a.Name}: {(a.On ? "activo" : "DESACTIVADO")}{(a.On && !a.UpToDate ? ", firmas antiguas" : "")}"));
            list.Add(new SecurityFinding("antivirus", "Antivirus", ok, text));
        });

        // Windows Update
        Try(() =>
        {
            using var wu = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\wuauserv");
            using var au = hklm.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
            bool disabled = Convert.ToInt32(wu?.GetValue("Start") ?? 3) == 4;
            bool policyOff = Convert.ToInt32(au?.GetValue("NoAutoUpdate") ?? 0) == 1;
            list.Add(new SecurityFinding("update", "Actualizaciones de Windows", !disabled && !policyOff,
                disabled ? "El servicio Windows Update está DESACTIVADO: el PC no recibe parches de seguridad."
                : policyOff ? "Las actualizaciones automáticas están desactivadas por una directiva."
                : "Funcionan."));
        });

        // Escritorio remoto
        Try(() =>
        {
            using var ts = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
            bool open = Convert.ToInt32(ts?.GetValue("fDenyTSConnections") ?? 1) == 0;
            list.Add(new SecurityFinding("rdp", "Escritorio remoto", !open,
                open ? "ACTIVADO: se puede manejar este PC desde otro. Si nadie lo usa, mejor apagarlo (Configuración > Sistema > Escritorio remoto)."
                     : "Desactivado."));
        });

        // Control de cuentas (UAC)
        Try(() =>
        {
            using var sys = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            bool lua = Convert.ToInt32(sys?.GetValue("EnableLUA") ?? 1) != 0;
            bool silent = Convert.ToInt32(sys?.GetValue("ConsentPromptBehaviorAdmin") ?? 5) == 0;
            list.Add(new SecurityFinding("uac", "Control de cuentas de usuario", lua && !silent,
                !lua ? "DESACTIVADO: cualquier programa puede hacerse administrador sin preguntar."
                : silent ? "Los administradores no reciben la pregunta de \"¿Quieres permitir...?\": los programas se elevan solos."
                : "Activado."));
        });

        // Herramientas bloqueadas (para todos y para cada usuario con la sesión abierta)
        Try(() =>
        {
            var blocked = new List<string>();
            void Look(RegistryKey? root, string who)
            {
                using var sys = root?.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System");
                using var exp = root?.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
                if (Convert.ToInt32(sys?.GetValue("DisableTaskMgr") ?? 0) == 1) blocked.Add($"Administrador de tareas ({who})");
                if (Convert.ToInt32(sys?.GetValue("DisableRegistryTools") ?? 0) >= 1) blocked.Add($"Editor del registro ({who})");
                if (Convert.ToInt32(exp?.GetValue("NoFolderOptions") ?? 0) == 1) blocked.Add($"Opciones de carpeta ({who})");
            }
            Look(hklm, "todos");
            using var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            foreach (var u in StartupItems.Users().Where(u => u.Loaded))
            {
                using var root = hku.OpenSubKey(u.Sid);
                Look(root, u.Name);
            }
            list.Add(new SecurityFinding("tools", "Herramientas de Windows", blocked.Count == 0,
                blocked.Count == 0 ? "Ninguna bloqueada."
                : "BLOQUEADO: " + string.Join(", ", blocked) + ". Algunos virus lo hacen para que no se les pueda quitar (si no lo has puesto tú a propósito)."));
        });

        return list;
    }
}
