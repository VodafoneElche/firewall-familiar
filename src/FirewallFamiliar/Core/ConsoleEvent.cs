using System;
using System.Net;

namespace FirewallFamiliar.Core;

/// <summary>
/// Un mensaje de la consola. Si trae programa o dirección IP, al pincharlo
/// se abre una ficha con todos los detalles.
/// </summary>
public sealed class ConsoleEvent
{
    public DateTime Time { get; init; } = DateTime.Now;
    public string Text { get; init; } = "";

    /// <summary>Ruta del programa relacionado (o "System"), si lo hay.</summary>
    public string? AppPath { get; init; }
    public int Pid { get; init; }
    public IPAddress? RemoteAddress { get; init; }
    public int RemotePort { get; init; }
    public string Protocol { get; init; } = "";
    public bool Inbound { get; init; }
    /// <summary>Qué ocurrió, en pocas palabras: "Bloqueado", "Permitido", "Pregunta"...</summary>
    public string Outcome { get; init; } = "";

    public bool HasDetails => !string.IsNullOrEmpty(AppPath) || RemoteAddress != null;

    public string Display => $"{Time:dd/MM/yyyy HH:mm:ss}  {Text}";
}
