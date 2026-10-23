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

    /// <summary>Si es true, los valores son bytes/s y la escala se muestra como B, KB, MB.</summary>
    public bool IsBytes { get; set; } = true;

    /// <summary>Valor mínimo de la escala vertical, para que el ruido pequeño no llene la gráfica.</summary>
    public double MinScale { get; set; } = 1024;

    public int MaxSamples { get; set; } = 120;

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
        for (int i = 0; i <= 4; i++)
        {
            double y = plot.Top + i * plot.Height / 4;
            dc.DrawLine(GridPen, new Point(plot.Left, y), new Point(plot.Right, y));
        }

        // Escala
        double max = Math.Max(MinScale, Math.Max(_total.DefaultIfEmpty(0).Max(), _blocked.DefaultIfEmpty(0).Max()));
        max = NiceCeiling(max);
        DrawText(dc, Label(max), new Point(4, plot.Top - 2), TitleBrush, 10);
        DrawText(dc, Label(0), new Point(4, plot.Bottom - 13), TitleBrush, 10);

        // Título y leyenda
        DrawText(dc, Title, new Point(left + 4, 3), TitleBrush, 12, bold: true);
        var legend = new FormattedText("— Total", CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            Font, 11, TitleBrush, VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(legend, new Point(w - right - legend.Width - 4, 4));
        DrawText(dc, "— Bloqueado", new Point(w - right - legend.Width - 80, 4), BlockedBrush, 11);

        // Líneas
        DrawSeries(dc, _blocked, BlockedPen, plot, max);
        DrawSeries(dc, _total, TotalPen, plot, max);
    }

    private void DrawSeries(DrawingContext dc, List<double> data, Pen pen, Rect plot, double max)
    {
        if (data.Count < 2) return;
        double dx = plot.Width / (MaxSamples - 1);
        double startX = plot.Right - (data.Count - 1) * dx;
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            for (int i = 0; i < data.Count; i++)
            {
                var pt = new Point(startX + i * dx, plot.Bottom - Math.Min(1, data[i] / max) * plot.Height);
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
    private double _peak = 1024;

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
        // El pico decae poco a poco para que la escala se adapte
        _peak = Math.Max(1024, Math.Max(_peak * 0.97, bytesPerSecond));
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
        int lit = (int)Math.Ceiling(Math.Min(1, _value / _peak) * bars);
        for (int i = 0; i < bars; i++)
        {
            double y = bottom - (i + 1) * barH;
            dc.DrawRectangle(i < lit ? On : Off, null, new Rect(w * 0.25, y + 1, w * 0.5, barH - 2));
        }

        var val = new FormattedText(Format.Bytes((long)_value) + "/s", CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, Font, 10, On, dip);
        dc.DrawText(val, new Point((w - val.Width) / 2, h - 32));
        var blk = new FormattedText(Format.Bytes((long)_blocked) + "/s", CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, Font, 10, Red, dip);
        dc.DrawText(blk, new Point((w - blk.Width) / 2, h - 17));
    }

    private static Brush Make(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
}
