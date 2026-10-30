using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;

namespace FirewallFamiliar.Core;

/// <summary>Estado de un disco físico según el propio disco (SMART) y Windows.</summary>
public sealed class DiskStatus
{
    public string Id { get; init; } = "";
    public string Model { get; init; } = "";
    public string Type { get; init; } = "";
    public long Size { get; init; }
    public string Health { get; init; } = "";
    public bool PredictsFailure { get; set; }
    public int? Temperature { get; init; }
    public int? Wear { get; init; }
    public long? ReadErrors { get; init; }
    public long? WriteErrors { get; init; }
    public long? PowerOnHours { get; init; }

    /// <summary>Problemas graves (null si está bien).</summary>
    public string? Problem
    {
        get
        {
            var p = new List<string>();
            if (PredictsFailure) p.Add("el propio disco avisa de que va a fallar (SMART)");
            if (Health == "Mal") p.Add("Windows dice que está en mal estado");
            else if (Health == "Aviso") p.Add("Windows da un aviso sobre su estado");
            if (ReadErrors > 0 || WriteErrors > 0) p.Add($"tiene errores que no ha podido corregir (lectura {ReadErrors ?? 0}, escritura {WriteErrors ?? 0})");
            if (Wear >= 90) p.Add($"está gastado al {Wear}% (un SSD dura hasta el 100%)");
            if (Temperature >= 70) p.Add($"está muy caliente ({Temperature} °C)");
            return p.Count == 0 ? null : string.Join("; ", p);
        }
    }

    public string Summary => Problem == null ? "✔ Bien" : "⚠ " + Problem;
    public string SizeText => Size > 0 ? $"{Size / 1e9:0} GB" : "";
    public string TemperatureText => Temperature is { } t and > 0 ? $"{t} °C" : "";
    public string WearText => Wear is { } w ? $"{w}%" : "";
    public string HoursText => PowerOnHours is { } h and > 0 ? $"{h:N0} h" : "";
}

/// <summary>Espacio libre de una unidad (C:, D:...).</summary>
public sealed record VolumeStatus(string Name, string Label, long Total, long Free)
{
    public double FreePercent => Total > 0 ? 100.0 * Free / Total : 100;
    public bool Low => Total > 0 && (FreePercent < 10 || Free < 5L * 1024 * 1024 * 1024);
    public string Text => $"{Name} {Label}: libres {Models.Format.Bytes(Free)} de {Models.Format.Bytes(Total)} ({FreePercent:0}%)" + (Low ? " ⚠ poco espacio" : "");
}

/// <summary>
/// Salud de los discos con lo que ya trae Windows (WMI de almacenamiento y SMART). Necesita
/// permisos de administrador para los contadores (el servicio los tiene). No usa Internet.
/// </summary>
public static class DiskHealth
{
    public static List<DiskStatus> Check()
    {
        var counters = new Dictionary<string, ManagementBaseObject>();
        try
        {
            using var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Storage", "SELECT * FROM MSFT_StorageReliabilityCounter");
            foreach (var c in s.Get()) counters[c["DeviceId"]?.ToString() ?? ""] = c;
        }
        catch { }

        var failing = new List<string>();
        try
        {
            using var s = new ManagementObjectSearcher(@"root\wmi", "SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus");
            foreach (var f in s.Get())
                if (f["PredictFailure"] is true) failing.Add((f["InstanceName"]?.ToString() ?? "").ToLowerInvariant());
        }
        catch { }

        var list = new List<DiskStatus>();
        using (var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Storage",
                   "SELECT DeviceId, FriendlyName, MediaType, BusType, HealthStatus, Size FROM MSFT_PhysicalDisk"))
            foreach (var d in s.Get())
            {
                string id = d["DeviceId"]?.ToString() ?? "";
                string model = (d["FriendlyName"]?.ToString() ?? "").Trim();
                int media = Convert.ToInt32(d["MediaType"] ?? 0);
                int bus = Convert.ToInt32(d["BusType"] ?? 0);
                int health = Convert.ToInt32(d["HealthStatus"] ?? 5);
                counters.TryGetValue(id, out var c);
                // SMART dice el modelo en el nombre de la instancia
                string key = new string(model.ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
                bool predict = failing.Any(f => key.Length > 3 && new string(f.Where(char.IsLetterOrDigit).ToArray()).Contains(key));
                list.Add(new DiskStatus
                {
                    Id = id, Model = model,
                    Type = (media switch { 3 => "Disco duro (HDD)", 4 => "SSD", 5 => "SCM", _ => "Disco" }) + (bus == 17 ? " NVMe" : bus == 7 ? " USB" : ""),
                    Size = Convert.ToInt64(d["Size"] ?? 0L),
                    Health = health switch { 0 => "Bien", 1 => "Aviso", 2 => "Mal", _ => "Desconocido" },
                    PredictsFailure = predict,
                    Temperature = Num(c, "Temperature") is { } t and > 0 and < 150 ? (int)t : null,
                    Wear = Num(c, "Wear") is { } w and >= 0 and <= 100 && media == 4 ? (int)w : null,
                    ReadErrors = Num(c, "ReadErrorsUncorrected"),
                    WriteErrors = Num(c, "WriteErrorsUncorrected"),
                    PowerOnHours = Num(c, "PowerOnHours")
                });
            }
        // Si solo hay un disco, el aviso de SMART es suyo aunque el nombre no coincida
        if (failing.Count > 0 && list.Count == 1) list[0].PredictsFailure = true;
        return list;
    }

    private static long? Num(ManagementBaseObject? o, string prop)
    {
        try { return o?[prop] is { } v ? Convert.ToInt64(v) : null; } catch { return null; }
    }

    public static List<VolumeStatus> Volumes() =>
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => new VolumeStatus(d.Name.TrimEnd('\\'), d.VolumeLabel, d.TotalSize, d.AvailableFreeSpace)).ToList();
}
