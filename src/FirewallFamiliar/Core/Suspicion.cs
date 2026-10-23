using System.IO;

namespace FirewallFamiliar.Core;

/// <summary>Pistas para saber si un programa puede ser sospechoso.</summary>
public static class Suspicion
{
    /// <summary>Carpetas donde un programa normal no suele vivir. Devuelve su nombre en palabras, o null.</summary>
    public static string? OddFolder(string path)
    {
        string p = path.ToLowerInvariant();
        if (p.Contains(@"\appdata\local\temp\") || p.Contains(@"\windows\temp\")) return "una carpeta de archivos temporales";
        if (p.Contains(@"\downloads\") || p.Contains(@"\descargas\")) return "la carpeta de Descargas";
        if (p.Contains(@"\users\public\")) return "la carpeta Pública";
        if (p.Contains(@"\$recycle.bin\")) return "la Papelera";
        string dir = (Path.GetDirectoryName(p) ?? "").TrimEnd('\\');
        if (dir.EndsWith(@"\appdata\roaming") || dir.EndsWith(@"\appdata\local")) return "la raíz de AppData";
        if (dir.EndsWith(@":\programdata")) return "la raíz de ProgramData";
        if (dir.Length == 2 && dir[1] == ':') return "la raíz del disco";
        return null;
    }
}
