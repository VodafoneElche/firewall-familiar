namespace FirewallFamiliar.Core;

/// <summary>Para qué se usa normalmente cada puerto, explicado de forma sencilla.</summary>
public static class Ports
{
    public static string Describe(int port, string protocol = "") => port switch
    {
        80 => "páginas web (sin cifrar)",
        443 => protocol == "UDP" ? "páginas web y vídeo (QUIC)" : "páginas web seguras (https)",
        53 => "consulta de nombres (DNS): averiguar la dirección de una web",
        853 => "consulta de nombres cifrada (DNS sobre TLS)",
        123 => "poner el reloj en hora",
        67 or 68 => "obtener dirección en la red de casa (DHCP)",
        5353 => "descubrir aparatos en la red de casa (mDNS)",
        1900 => "descubrir aparatos en la red de casa (UPnP)",
        137 or 138 or 139 or 445 => "carpetas e impresoras compartidas de Windows",
        21 => "transferencia de archivos (FTP)",
        22 => "acceso remoto seguro (SSH)",
        23 => "acceso remoto antiguo (Telnet)",
        25 or 465 or 587 => "envío de correo",
        110 or 995 => "recepción de correo (POP)",
        143 or 993 => "recepción de correo (IMAP)",
        3389 => "escritorio remoto de Windows",
        5222 or 5223 => "mensajería (chat)",
        3478 or 3479 or 3480 or 3481 => "llamadas y videollamadas",
        5228 => "notificaciones de Google",
        6881 or 6882 or 6883 or 6884 or 6885 or 6886 or 6887 or 6888 or 6889 => "descargas P2P (BitTorrent)",
        27015 or 27016 or 27017 or 27018 or 27019 or 27020 => "juegos en línea (Steam)",
        3074 => "juegos en línea (Xbox)",
        25565 => "juegos en línea (Minecraft)",
        >= 49152 => "puerto temporal (lo elige el programa)",
        _ => ""
    };
}
