using System;
using System.Collections.Generic;
using System.Windows;
using Forms = System.Windows.Forms;
using Drawing = System.Drawing;

namespace FirewallFamiliar.Core;

/// <summary>
/// Icono junto al reloj, como el de Sygate: el escudo FF entre dos flechas.
/// La verde (bajando) se enciende cuando entran datos y la roja (subiendo) cuando salen.
/// En "Bloquear todo" el escudo se pone rojo.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon = new();
    private readonly Dictionary<string, Drawing.Icon> _icons = new();
    private string _current = "";
    private readonly Forms.ToolStripMenuItem _modeAllow, _modeAsk, _modeBlock, _blockAll;

    public event Action? OpenRequested;
    public event Action? ExitRequested;
    public event Action? LogsRequested;
    public event Action? BlockAllRequested;
    public event Action<FirewallMode>? ModeRequested;
    /// <summary>Se pulsó sobre el último globo de aviso.</summary>
    public event Action? AlertClicked;

    public TrayIcon()
    {
        foreach (var name in new[] { "nada", "entra", "sale", "ambos" })
        {
            _icons[name] = Load($"tray-{name}.ico");
            _icons["bloq-" + name] = Load($"tray-bloq-{name}.ico");
        }

        var menu = new Forms.ContextMenuStrip();
        var open = new Forms.ToolStripMenuItem("Abrir Firewall Familiar", null, (_, _) => OpenRequested?.Invoke())
        { Font = new Drawing.Font(menu.Font, Drawing.FontStyle.Bold) };
        menu.Items.Add(open);
        menu.Items.Add(new Forms.ToolStripSeparator());
        _modeAllow = new Forms.ToolStripMenuItem("Sin preguntas", null, (_, _) => ModeRequested?.Invoke(FirewallMode.SinPreguntas));
        _modeAsk = new Forms.ToolStripMenuItem("Preguntar", null, (_, _) => ModeRequested?.Invoke(FirewallMode.Preguntar));
        _modeBlock = new Forms.ToolStripMenuItem("Bloquear todo", null, (_, _) => ModeRequested?.Invoke(FirewallMode.BloquearTodo));
        menu.Items.Add(new Forms.ToolStripMenuItem("Modo de seguridad", null, _modeAllow, _modeAsk, _modeBlock));
        _blockAll = new Forms.ToolStripMenuItem("Bloquear todo ahora", null, (_, _) => BlockAllRequested?.Invoke());
        menu.Items.Add(_blockAll);
        menu.Items.Add(new Forms.ToolStripMenuItem("Registros...", null, (_, _) => LogsRequested?.Invoke()));
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(new Forms.ToolStripMenuItem("Salir", null, (_, _) => ExitRequested?.Invoke()));

        _icon.ContextMenuStrip = menu;
        _icon.Text = "Firewall Familiar";
        _icon.DoubleClick += (_, _) => OpenRequested?.Invoke();
        _icon.BalloonTipClicked += (_, _) => AlertClicked?.Invoke();
        Set(false, false, false);
        _icon.Visible = true;
    }

    private static Drawing.Icon Load(string file)
    {
        var info = Application.GetResourceStream(new Uri($"pack://application:,,,/Assets/{file}"));
        using var s = info!.Stream;
        return new Drawing.Icon(s, Forms.SystemInformation.SmallIconSize);
    }

    /// <summary>Enciende las flechas según si en el último segundo han entrado o salido datos.</summary>
    public void Set(bool incoming, bool outgoing, bool blockAll)
    {
        string name = (blockAll ? "bloq-" : "") + (incoming && outgoing ? "ambos" : incoming ? "entra" : outgoing ? "sale" : "nada");
        if (name == _current) return;
        _current = name;
        _icon.Icon = _icons[name];
    }

    public void SetMode(FirewallMode mode)
    {
        _modeAllow.Checked = mode == FirewallMode.SinPreguntas;
        _modeAsk.Checked = mode == FirewallMode.Preguntar;
        _modeBlock.Checked = mode == FirewallMode.BloquearTodo;
        _blockAll.Text = mode == FirewallMode.BloquearTodo ? "Desbloquear" : "Bloquear todo ahora";
        string text = "Firewall Familiar - " + mode switch
        {
            FirewallMode.SinPreguntas => "Sin preguntas",
            FirewallMode.Preguntar => "Preguntar",
            _ => "TODO BLOQUEADO"
        };
        _icon.Text = text.Length > 63 ? text[..63] : text;
    }

    /// <summary>Texto al pasar el ratón por encima del icono.</summary>
    public void SetText(string text) => _icon.Text = text.Length > 63 ? text[..63] : text;

    public bool Visible
    {
        get => _icon.Visible;
        set { if (_icon.Visible != value) _icon.Visible = value; }
    }

    public void Alert(string title, string text, bool warning)
    {
        _icon.ShowBalloonTip(8000, title, text.Length > 250 ? text[..250] + "..." : text,
            warning ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        foreach (var i in _icons.Values) i.Dispose();
    }
}
