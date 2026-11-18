using System;
using System.Collections.Generic;

namespace FirewallFamiliar.Core;

/// <summary>
/// Ordenadores de la familia, conocidos por su MAC (la de su tarjeta Wi-Fi o de cable).
/// Salen con su nombre y como "de casa", y nunca dan aviso de aparato nuevo.
/// Los móviles no están: cambian de MAC (dirección privada). Para añadir un PC nuevo, se pone aquí
/// y sale en la siguiente versión; mientras, se le puede poner nombre en Router > Aparatos de la red.
/// </summary>
public static class Family
{
    private static readonly Dictionary<string, (string Name, string Kind)> Known = new(StringComparer.OrdinalIgnoreCase)
    {
        ["10-FF-E0-A7-EE-E4"] = ("Sobremesa de Daniel", "sobremesa"),
        ["F4-26-79-2D-86-C9"] = ("Portátil de Jose (Wi-Fi)", "portatil"),
        ["34-5A-60-33-36-75"] = ("PC de Alejandro", "sobremesa"),
        ["C8-3D-D4-95-24-F9"] = ("Portátil de Elena", "portatil"),
    };

    public static (string Name, string Kind)? Lookup(string mac) =>
        Known.TryGetValue(mac, out var f) ? f : null;
}
