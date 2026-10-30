using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using FirewallFamiliar.Models;

namespace FirewallFamiliar.Controls;

/// <summary>
/// Gráfica de historial al estilo Sygate: fondo negro, rejilla verde y dos líneas
/// (total en verde, bloqueado en rojo). Se desplaza hacia la izquierda con cada muestra.
/// </summary>
public sealed class TrafficGraph : FrameworkElement
{
    private readonly List<double> _total = new();
    private readonly List<double> _blocked = new();
    private int _scroll; // desplaza la rejilla para dar sensación de movimiento

    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(TrafficGraph),
            new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.AffectsRender));

    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }

    /// <summary>
    /// Si es true, los valores son bytes/s y la escala es fija de 0 a 1 Gbps (en bits, como la velocidad de la fibra),
    /// con un escalón por cada ×10 para que se vea igual de bien una web (Kbps) que una descarga grande (cientos de Mbps).
    /// </summary>
    public bool IsBytes { get; set; } = true;

    /// <summary>Valor mínimo de la escala vertical, para que el ruido pequeño no llene la gráfica.</summary>
    public double MinScale { get; set; } = 1024;

    public int MaxSamples { get; set; } = 120;

    /// <summary>Leyenda de la línea verde y de la roja.</summary>
    public string TotalLabel { get; set; } = "Total";
    public string BlockedLabel { get; set; } = "Bloqueos";

    private static readonly Pen GridPen = MakePen(Color.FromRgb(0, 80, 0), 1);
    private static readonly Pen TotalPen = MakePen(Color.FromRgb(0, 230, 0), 1.5);
    private static readonly Pen BlockedPen = MakePen(Color.FromRgb(230, 30, 30), 1.5);
    private static readonly Brush TitleBrush = MakeBrush(Color.FromRgb(0, 230, 0));
    private static readonly Brush BlockedBrush = MakeBrush(Color.FromRgb(230, 30, 30));
    private static readonly Typeface Font = new("Segoe UI");

    public void AddSample(double total, double blocked)
    {
        _total.Add(total);
        _blocked.Add(blocked);
        if (_total.Count > MaxSamples) { _total.RemoveAt(0); _blocked.RemoveAt(0); }
        _scroll = (_scroll + 1) % 10;
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w < 20 || h < 20) return;

        dc.DrawRectangle(Brushes.Black, null, new Rect(0, 0, w, h));

        const double left = 44, top = 22, bottom = 6, right = 6;
        var plot = new Rect(left, top, Math.Max(1, w - left - right), Math.Max(1, h - top - bottom));

        // Rejilla
        double step = plot.Width / 12;
        for (int i = 0; i <= 12; i++)
        {
            double x = plot.Left + i * step - (_scroll * step / 10);
            if (x >= plot.Left) dc.DrawLine(GridPen, new Point(x, plot.Top), new Point(x, plot.Bottom));
        }
        int rows = IsBytes ? SpeedSteps.Length : 4;
        for (int i = 0; i <= rows; i++)
        {
            double y = plot.Top + i * plot.Height / rows;
            dc.DrawLine(GridPen, new Point(plot.Left, y), new Point(plot.Right, y));
        }

        // Escala (la línea roja de bloqueos usa su propia escala: son conexiones, no bytes)
        double max = IsBytes ? 0 : NiceCeiling(Math.Max(MinScale, _total.DefaultIfEmpty(0).Max()));
        double blockedMax = Math.Max(5, _blocked.DefaultIfEmpty(0).Max());
        if (IsBytes)
        {
            // De arriba abajo: 1G, 100M, 10M, 1M, 100K, 10K y 0 (1 Kbps o menos)
            for (int i = 0; i < SpeedSteps.Length; i++)
                DrawText(dc, SpeedSteps[i], new Point(4, plot.Top + i * plot.Height / rows - (i == 0 ? 2 : 7)), TitleBrush, 10);
            DrawText(dc, "0", new Point(4, plot.Bottom - 13), TitleBrush, 10);
        }
        else
        {
            DrawText(dc, Label(max), new Point(4, plot.Top - 2), TitleBrush, 10);
            DrawText(dc, Label(0), new Point(4, plot.Bottom - 13), TitleBrush, 10);
        }

        // Título (con la velocidad de ahora) y leyenda
        string title = IsBytes && _total.Count > 0 ? $"{Title}  ·  {Format.Speed(_total[^1])}" : Title;
        DrawText(dc, title, new Point(left + 4, 3), TitleBrush, 12, bold: true);
        double dip = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var legend = new FormattedText("— " + TotalLabel, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            Font, 11, TitleBrush, dip);
        var legendRed = new FormattedText("— " + BlockedLabel, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            Font, 11, BlockedBrush, dip);
        double legendY = w > 380 ? 4 : 18; // si la gráfica es estrecha, la leyenda baja una línea
        dc.DrawText(legend, new Point(w - right - legend.Width - 4, legendY));
        dc.DrawText(legendRed, new Point(w - right - legend.Width - legendRed.Width - 14, legendY));

        // Líneas
        DrawSeries(dc, _blocked, BlockedPen, plot, v => v / blockedMax);
        DrawSeries(dc, _total, TotalPen, plot, IsBytes ? SpeedFraction : v => v / max);
    }

    /// <summary>Marcas de la escala de velocidad, de arriba abajo (cada una es ×10 la de debajo).</summary>
    private static readonly string[] SpeedSteps = { "1 Gbps", "100 M", "10 M", "1 M", "100 K", "10 K" };

    /// <summary>
    /// Altura (0 a 1) de una velocidad en bytes/s en la escala de 1 Kbps a 1 Gbps: un escalón por cada ×10.
    /// También la usa el medidor de barras.
    /// </summary>
    public static double SpeedFraction(double bytesPerSecond)
    {
        double bits = bytesPerSecond * 8;
        if (bits <= 1000) return 0;
        return Math.Min(1, Math.Log10(bits / 1000) / 6);
    }

    private void DrawSeries(DrawingContext dc, List<double> data, Pen pen, Rect plot, Func<double, double> height)
    {
        if (data.Count < 2) return;
        double dx = plot.Width / (MaxSamples - 1);
        double startX = plot.Right - (data.Count - 1) * dx;
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            for (int i = 0; i < data.Count; i++)
            {
                var pt = new Point(startX + i * dx, plot.Bottom - Math.Min(1, height(data[i])) * plot.Height);
                if (i == 0) ctx.BeginFigure(pt, false, false); else ctx.LineTo(pt, true, false);
            }
        }
        geo.Freeze();
        dc.DrawGeometry(null, pen, geo);
    }

    private string Label(double v) => IsBytes ? Format.Bytes((long)v) : v.ToString("0", CultureInfo.CurrentCulture);

    private static double NiceCeiling(double v)
    {
        double p = Math.Pow(10, Math.Floor(Math.Log10(v)));
        foreach (var m in new[] { 1, 2, 5, 10 })
            if (m * p >= v) return m * p;
        return 10 * p;
    }

    private void DrawText(DrawingContext dc, string text, Point at, Brush brush, double size, bool bold = false)
    {
        var ft = new FormattedText(text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            bold ? new Typeface(Font.FontFamily, FontStyles.Normal, FontWeights.Bold, FontStretches.Normal) : Font,
            size, brush, VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(ft, at);
    }

    private static Pen MakePen(Color c, double t) { var p = new Pen(MakeBrush(c), t); p.Freeze(); return p; }
    private static Brush MakeBrush(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
}

/// <summary>
/// Medidor vertical de barras verdes (como el "Incoming / Outgoing" de Sygate),
/// con el valor actual debajo.
/// </summary>
public sealed class TrafficMeter : FrameworkElement
{
    private double _value;
    private double _blocked;

    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(TrafficMeter),
            new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.AffectsRender));

    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }

    private static readonly Brush On = Make(Color.FromRgb(0, 230, 0));
    private static readonly Brush Off = Make(Color.FromRgb(0, 70, 0));
    private static readonly Brush Red = Make(Color.FromRgb(230, 30, 30));
    private static readonly Typeface Font = new("Segoe UI");

    public void Update(double bytesPerSecond, double blockedPerSecond)
    {
        _value = bytesPerSecond;
        _blocked = blockedPerSecond;
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w < 10 || h < 40) return;
        dc.DrawRectangle(Brushes.Black, null, new Rect(0, 0, w, h));
        double dip = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        var title = new FormattedText(Title, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            new Typeface(Font.FontFamily, FontStyles.Normal, FontWeights.Bold, FontStretches.Normal), 11, On, dip);
        dc.DrawText(title, new Point((w - title.Width) / 2, 3));

        double top = 22, bottom = h - 34;
        const int bars = 12;
        double barH = (bottom - top) / bars;
        // Misma escala que la gráfica: de 1 Kbps a 1 Gbps, dos barras por cada ×10
        int lit = (int)Math.Ceiling(TrafficGraph.SpeedFraction(_value) * bars);
        for (int i = 0; i < bars; i++)
        {
            double y = bottom - (i + 1) * barH;
            dc.DrawRectangle(i < lit ? On : Off, null, new Rect(w * 0.25, y + 1, w * 0.5, barH - 2));
        }

        var val = new FormattedText(Format.Speed(_value), CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, Font, 10, On, dip);
        dc.DrawText(val, new Point((w - val.Width) / 2, h - 32));
        var blk = new FormattedText(_blocked == 0 ? "0 bloq." : $"{_blocked:0} bloq.", CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, Font, 10, Red, dip);
        dc.DrawText(blk, new Point((w - blk.Width) / 2, h - 17));
    }

    private static Brush Make(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
}
