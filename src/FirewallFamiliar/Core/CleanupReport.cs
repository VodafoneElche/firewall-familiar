using System;
using System.Linq;
using System.Text;

namespace FirewallFamiliar.Core;

/// <summary>Sección del informe con el estado de ahora: discos, chequeo de seguridad, lo que arranca solo y restos.</summary>
public static class CleanupReport
{
    public static string Section()
    {
        var sb = new StringBuilder();
        sb.AppendLine("## 10. Arranque, restos de programas, discos y chequeo de seguridad");
        sb.AppendLine();
        sb.AppendLine($"Estado en el momento de hacer el informe ({DateTime.Now:dd/MM/yyyy HH:mm}).");
        sb.AppendLine();

        sb.AppendLine("### Discos");
        sb.AppendLine();
        try
        {
            var disks = DiskHealth.Check();
            if (disks.Count == 0) sb.AppendLine("- Windows no ha dado información de los discos.");
            foreach (var d in disks)
                sb.AppendLine($"- {d.Model} ({d.Type}, {d.SizeText}): {d.Summary}. Estado según Windows: {d.Health}" +
                              (d.TemperatureText.Length > 0 ? $", temperatura {d.TemperatureText}" : "") +
                              (d.WearText.Length > 0 ? $", desgaste {d.WearText}" : "") +
                              (d.HoursText.Length > 0 ? $", encendido {d.HoursText}" : "") +
                              (d.ReadErrors != null ? $", errores sin corregir {d.ReadErrors + (d.WriteErrors ?? 0)}" : ""));
        }
        catch (Exception ex) { sb.AppendLine("- No se pudo leer: " + ex.Message); }
        try { foreach (var v in DiskHealth.Volumes()) sb.AppendLine("- " + v.Text); } catch { }
        sb.AppendLine();

        var artifacts = SpyIndicators.CheckArtifacts();
        sb.AppendLine($"### Huellas de puertas traseras y programas espía en el disco ({SpyIndicators.ArtifactCount} comprobadas)");
        sb.AppendLine();
        if (artifacts.Count == 0) sb.AppendLine("Ninguna encontrada.");
        foreach (var (what, family) in artifacts) sb.AppendLine($"- ⚠ {family}: {what}");
        sb.AppendLine();

        sb.AppendLine("### Chequeo de seguridad de Windows");
        sb.AppendLine();
        foreach (var f in SecurityCheck.Run())
            sb.AppendLine($"- {(f.Ok ? "✔" : "⚠")} {f.Name}: {f.Text}");
        sb.AppendLine();

        var items = StartupItems.Collect();
        var shown = items.Where(i => !i.IsMicrosoft || i.Risk != null)
            .OrderByDescending(i => i.Level).ThenBy(i => i.Kind).ThenBy(i => i.Name).ToList();
        sb.AppendLine($"### Lo que arranca solo ({shown.Count} que no son de Microsoft, de {items.Count} en total)");
        sb.AppendLine();
        sb.AppendLine("Inicio de Windows, carpetas de Inicio, tareas programadas, servicios automáticos, menú contextual, " +
                      "protocolos de red, secuestros de programas y ajustes del navegador. \"Activo = no\" es que se ha desactivado.");
        sb.AppendLine();
        sb.AppendLine("| Nivel | Tipo | Nombre | Usuario | Activo | Firma | Archivo o valor | Motivo |");
        sb.AppendLine("|---|---|---|---|---|---|---|---|");
        foreach (var i in shown.Take(200))
            sb.AppendLine($"| {i.LevelText} | {i.Kind} | {Cell(i.Name)} | {Cell(i.User)} | {(i.Enabled ? "sí" : "no")} | {Cell(i.SignatureText)} | " +
                          $"{Cell(i.IsSetting ? i.Command : i.Path)} | {Cell(i.RiskText)} |");
        sb.AppendLine();

        var rests = Leftovers.Find(items.Where(i => i.Enabled).Select(i => i.Path));
        sb.AppendLine($"### Posibles restos de programas desinstalados ({rests.Count})");
        sb.AppendLine();
        if (rests.Count == 0) sb.AppendLine("Ninguno.");
        else
        {
            sb.AppendLine($"Carpetas que no son de ningún programa instalado y no han cambiado en {Leftovers.Quiet.TotalDays:0} días, o de programas basura conocidos.");
            sb.AppendLine();
            sb.AppendLine("| Estado | Carpeta | Dónde | Tamaño | Archivos | Último cambio |");
            sb.AppendLine("|---|---|---|---|---|---|");
            foreach (var r in rests.Take(80))
                sb.AppendLine($"| {r.StateText} | {Cell(r.Path)} | {Cell(r.Where)} | {r.SizeText} | {r.Files} | {r.LastChangeText} |");
        }
        sb.AppendLine();
        return sb.ToString();
    }

    private static string Cell(string s) => s.Replace("|", "/").Replace("\r", " ").Replace("\n", " ").Trim();
}
