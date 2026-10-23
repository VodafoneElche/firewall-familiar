using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using static FirewallFamiliar.Core.NativeMethods;

namespace FirewallFamiliar.Core;

/// <summary>Una conexión de red abierta por un programa.</summary>
public sealed record ConnectionInfo(
    int Pid,
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State)
{
    public bool IsListening => State == "Escuchando";
    public string Local => $"{LocalAddress}:{LocalPort}";
    public string Remote => RemotePort == 0 && (RemoteAddress is "0.0.0.0" or "::" or "") ? "" : $"{RemoteAddress}:{RemotePort}";
}

/// <summary>
/// Lee las tablas de conexiones TCP y UDP de Windows (lo mismo que muestra "netstat -ano").
/// </summary>
public static class ConnectionMonitor
{
    private static readonly string[] TcpStates =
    {
        "?", "Cerrada", "Escuchando", "SYN enviado", "SYN recibido", "Establecida",
        "FIN espera 1", "FIN espera 2", "Cerrando espera", "Cerrando", "Último ACK",
        "Espera de tiempo", "Borrando TCB"
    };

    public static List<ConnectionInfo> GetAll()
    {
        var list = new List<ConnectionInfo>();
        try { ReadTcp4(list); } catch { /* sin datos de este tipo */ }
        try { ReadTcp6(list); } catch { }
        try { ReadUdp4(list); } catch { }
        try { ReadUdp6(list); } catch { }
        return list;
    }

    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    private static string State(uint s) => s < TcpStates.Length ? TcpStates[s] : "?";

    private static IntPtr ReadTable(bool tcp, int af, int tableClass)
    {
        int size = 0;
        if (tcp) GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, tableClass, 0);
        else GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, tableClass, 0);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            size += 4096; // margen por si la tabla crece entre llamadas
            IntPtr buffer = Marshal.AllocHGlobal(size);
            uint result = tcp
                ? GetExtendedTcpTable(buffer, ref size, false, af, tableClass, 0)
                : GetExtendedUdpTable(buffer, ref size, false, af, tableClass, 0);
            if (result == 0) return buffer;
            Marshal.FreeHGlobal(buffer);
        }
        return IntPtr.Zero;
    }

    private static void ReadTcp4(List<ConnectionInfo> list)
    {
        IntPtr buf = ReadTable(true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (buf == IntPtr.Zero) return;
        try
        {
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buf + 4 + i * rowSize);
                list.Add(new ConnectionInfo(row.owningPid, "TCP",
                    new IPAddress(row.localAddr).ToString(), Port(row.localPort),
                    new IPAddress(row.remoteAddr).ToString(), Port(row.remotePort),
                    State(row.state)));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static unsafe void ReadTcp6(List<ConnectionInfo> list)
    {
        IntPtr buf = ReadTable(true, AF_INET6, TCP_TABLE_OWNER_PID_ALL);
        if (buf == IntPtr.Zero) return;
        try
        {
            int count = Marshal.ReadInt32(buf);
            int rowSize = sizeof(MIB_TCP6ROW_OWNER_PID);
            for (int i = 0; i < count; i++)
            {
                var row = (MIB_TCP6ROW_OWNER_PID*)(buf + 4 + i * rowSize);
                list.Add(new ConnectionInfo(row->owningPid, "TCPv6",
                    new IPAddress(new ReadOnlySpan<byte>(row->localAddr, 16)).ToString(), Port(row->localPort),
                    new IPAddress(new ReadOnlySpan<byte>(row->remoteAddr, 16)).ToString(), Port(row->remotePort),
                    State(row->state)));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void ReadUdp4(List<ConnectionInfo> list)
    {
        IntPtr buf = ReadTable(false, AF_INET, UDP_TABLE_OWNER_PID);
        if (buf == IntPtr.Zero) return;
        try
        {
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(buf + 4 + i * rowSize);
                list.Add(new ConnectionInfo(row.owningPid, "UDP",
                    new IPAddress(row.localAddr).ToString(), Port(row.localPort), "", 0, "Escuchando"));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static unsafe void ReadUdp6(List<ConnectionInfo> list)
    {
        IntPtr buf = ReadTable(false, AF_INET6, UDP_TABLE_OWNER_PID);
        if (buf == IntPtr.Zero) return;
        try
        {
            int count = Marshal.ReadInt32(buf);
            int rowSize = sizeof(MIB_UDP6ROW_OWNER_PID);
            for (int i = 0; i < count; i++)
            {
                var row = (MIB_UDP6ROW_OWNER_PID*)(buf + 4 + i * rowSize);
                list.Add(new ConnectionInfo(row->owningPid, "UDPv6",
                    new IPAddress(new ReadOnlySpan<byte>(row->localAddr, 16)).ToString(), Port(row->localPort),
                    "", 0, "Escuchando"));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
