using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace FirewallFamiliar.Models;

/// <summary>Tipo de proceso según cómo se deja ver en Windows.</summary>
public enum ProcessKind
{
    /// <summary>Tiene una ventana visible: el usuario lo ve.</summary>
    Ventana,
    /// <summary>Es un servicio registrado de Windows.</summary>
    Servicio,
    /// <summary>Componente del propio Windows sin ventana (en C:\Windows).</summary>
    Sistema,
    /// <summary>Sin ventana, pero pertenece a un programa que sí la tiene (p. ej. las pestañas de Chrome).</summary>
    SegundoPlano,
    /// <summary>Sin ventana, no es servicio y no está en C:\Windows: conviene revisarlo.</summary>
    Oculto
}

/// <summary>Una fila de la lista "Programas en ejecución".</summary>
public sealed class AppRow : INotifyPropertyChanged
{
    public AppRow(int pid) { Pid = pid; }

    public int Pid { get; }

    private string _name = "";
    public string Name { get => _name; set => Set(ref _name, value); }

    private string _description = "";
    public string Description { get => _description; set => Set(ref _description, value); }

    private string _version = "";
    public string Version { get => _version; set => Set(ref _version, value); }

    private string _path = "";
    public string Path { get => _path; set => Set(ref _path, value); }

    private string _serviceNames = "";
    /// <summary>Servicios de Windows que corren dentro de este proceso.</summary>
    public string ServiceNames { get => _serviceNames; set => Set(ref _serviceNames, value); }

    private ProcessKind _kind;
    public ProcessKind Kind
    {
        get => _kind;
        set { if (Set(ref _kind, value)) { Notify(nameof(KindText)); Notify(nameof(RowBrush)); } }
    }

    public string KindText => Kind switch
    {
        ProcessKind.Ventana => "Con ventana",
        ProcessKind.Servicio => "Servicio",
        ProcessKind.Sistema => "Sistema",
        ProcessKind.SegundoPlano => "Segundo plano",
        _ => "OCULTO"
    };

    private ImageSource? _icon;
    public ImageSource? Icon { get => _icon; set => Set(ref _icon, value); }

    private long _memory;
    public long Memory { get => _memory; set { if (Set(ref _memory, value)) Notify(nameof(MemoryText)); } }
    public string MemoryText => Format.Bytes(Memory);

    private double _cpu;
    public double Cpu { get => _cpu; set { if (Set(ref _cpu, value)) Notify(nameof(CpuText)); } }
    public string CpuText => Cpu < 0.05 ? "0" : Cpu.ToString("0.0");

    private long _bytesIn;
    public long BytesIn { get => _bytesIn; set { if (Set(ref _bytesIn, value)) Notify(nameof(BytesInText)); } }
    public string BytesInText => Format.Bytes(BytesIn);

    private long _bytesOut;
    public long BytesOut { get => _bytesOut; set { if (Set(ref _bytesOut, value)) Notify(nameof(BytesOutText)); } }
    public string BytesOutText => Format.Bytes(BytesOut);

    private long _rateIn;
    public long RateIn { get => _rateIn; set { if (Set(ref _rateIn, value)) Notify(nameof(RateText)); } }

    private long _rateOut;
    public long RateOut { get => _rateOut; set { if (Set(ref _rateOut, value)) Notify(nameof(RateText)); } }

    public string RateText => RateIn == 0 && RateOut == 0 ? "" : $"↓{Format.Bytes(RateIn)}/s ↑{Format.Bytes(RateOut)}/s";

    private int _connections;
    public int Connections { get => _connections; set { if (Set(ref _connections, value)) Notify(nameof(UsesNetwork)); } }

    private int _listening;
    /// <summary>Puertos abiertos esperando conexiones de fuera.</summary>
    public int Listening { get => _listening; set => Set(ref _listening, value); }

    public bool UsesNetwork => Connections > 0 || BytesIn > 0 || BytesOut > 0;

    private FirewallFamiliar.Core.RuleAction _rule;
    /// <summary>Regla del cortafuegos para este programa.</summary>
    public FirewallFamiliar.Core.RuleAction Rule
    {
        get => _rule;
        set { if (Set(ref _rule, value)) { Notify(nameof(RuleText)); Notify(nameof(RowBrush)); } }
    }

    public string RuleText => Rule switch
    {
        FirewallFamiliar.Core.RuleAction.Permitir => "✔ Permitir",
        FirewallFamiliar.Core.RuleAction.Bloquear => "✖ Bloquear",
        _ => "? Preguntar"
    };

    /// <summary>Color de fondo de la fila: rojo para los bloqueados, naranja para los ocultos.</summary>
    public Brush RowBrush =>
        Rule == FirewallFamiliar.Core.RuleAction.Bloquear ? BlockedBrush :
        Kind == ProcessKind.Oculto ? HiddenBrush : Brushes.Transparent;

    private static readonly Brush HiddenBrush = Freeze(new SolidColorBrush(Color.FromArgb(70, 255, 150, 0)));
    private static readonly Brush BlockedBrush = Freeze(new SolidColorBrush(Color.FromArgb(70, 230, 30, 30)));

    private static Brush Freeze(Brush b) { b.Freeze(); return b; }

    // ---------- Notificación de cambios a la interfaz ----------

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Notify(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value)) return false;
        field = value;
        Notify(name!);
        return true;
    }
}

public static class Format
{
    public static string Bytes(long b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024 * 1024) return $"{b / 1024.0:0.#} KB";
        if (b < 1024L * 1024 * 1024) return $"{b / 1024.0 / 1024:0.#} MB";
        return $"{b / 1024.0 / 1024 / 1024:0.##} GB";
    }
}
