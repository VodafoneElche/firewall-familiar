using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallFamiliar.Core;

/// <summary>
/// Mensaje entre el servicio (que hace el bloqueo) y el icono o la ventana de cada usuario.
/// Viaja como una línea JSON por una tubería con nombre ("named pipe") local.
/// </summary>
public sealed class PipeMessage
{
    /// <summary>
    /// Tipo. Del servicio: "estado", "pregunta", "cerrar-pregunta", "aviso", "respuesta-modo", "pausado".
    /// Del usuario: "hola", "respuesta", "modo", "desbloquear", "pausa".
    /// </summary>
    public string T { get; set; } = "";

    public FirewallMode Mode { get; set; }
    public bool Paused { get; set; }
    /// <summary>Sesión de Windows donde está abierta la ventana completa (0 = ninguna).</summary>
    public int GuiSession { get; set; }
    public bool HasPassword { get; set; }
    public bool ProtectAsk { get; set; }
    public bool ProtectRules { get; set; }
    public bool ProtectExit { get; set; }
    public bool TrayAlerts { get; set; }

    public int Id { get; set; }
    public string Path { get; set; } = "";
    public string Remote { get; set; } = "";
    public int RemotePort { get; set; }
    public string Protocol { get; set; } = "";

    public bool Allow { get; set; }
    public bool Remember { get; set; }
    public string Password { get; set; } = "";

    public string Title { get; set; } = "";
    public string Text { get; set; } = "";
    public bool Warning { get; set; }

    public bool Ok { get; set; }
    public string Error { get; set; } = "";
}

/// <summary>Lectura y escritura de mensajes por la tubería.</summary>
public sealed class PipeChannel : IDisposable
{
    public const string Name = "FirewallFamiliar";

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly PipeStream _pipe;
    private readonly StreamReader _reader;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public PipeChannel(PipeStream pipe)
    {
        _pipe = pipe;
        _reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
    }

    public PipeStream Stream => _pipe;
    public bool IsConnected => _pipe.IsConnected;

    /// <summary>Lee el siguiente mensaje. Devuelve null cuando el otro lado se ha ido.</summary>
    public async Task<PipeMessage?> ReadAsync(CancellationToken ct = default)
    {
        while (true)
        {
            string? line;
            try { line = await _reader.ReadLineAsync(ct); }
            catch { return null; }
            if (line == null) return null;
            if (line.Length == 0) continue;
            try { return JsonSerializer.Deserialize<PipeMessage>(line, Json); }
            catch { /* línea rota: se ignora */ }
        }
    }

    public async Task<bool> SendAsync(PipeMessage m)
    {
        byte[] data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(m, Json) + "\n");
        await _writeLock.WaitAsync();
        try
        {
            await _pipe.WriteAsync(data);
            await _pipe.FlushAsync();
            return true;
        }
        catch { return false; }
        finally { _writeLock.Release(); }
    }

    /// <summary>Se conecta al servicio. Devuelve null si no está funcionando.</summary>
    public static async Task<PipeChannel?> ConnectAsync(int timeoutMs)
    {
        var pipe = new NamedPipeClientStream(".", Name, PipeDirection.InOut, PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync(timeoutMs);
            return new PipeChannel(pipe);
        }
        catch
        {
            pipe.Dispose();
            return null;
        }
    }

    public void Dispose()
    {
        try { _pipe.Dispose(); } catch { }
        _reader.Dispose();
    }
}
