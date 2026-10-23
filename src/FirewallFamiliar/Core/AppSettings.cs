using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FirewallFamiliar.Core;

/// <summary>
/// Ajustes generales (contraseña y qué protege), en C:\ProgramData\FirewallFamiliar\ajustes.json.
/// La contraseña nunca se guarda tal cual: solo una "huella" (PBKDF2) de la que no se puede sacar.
/// </summary>
public sealed class AppSettings
{
    public string PasswordHash { get; set; } = "";
    public string PasswordSalt { get; set; } = "";
    /// <summary>Pedir la contraseña para cerrar el programa.</summary>
    public bool ProtectExit { get; set; } = true;
    /// <summary>Pedir la contraseña para cambiar reglas y modo.</summary>
    public bool ProtectRules { get; set; } = true;
    /// <summary>Pedir la contraseña al pulsar "Permitir" en la ventana de pregunta.</summary>
    public bool ProtectAsk { get; set; } = false;
    /// <summary>Avisos en globo junto al reloj (ataques, programas sospechosos).</summary>
    public bool TrayAlerts { get; set; } = true;

    public bool HasPassword => PasswordHash.Length > 0;

    private const int Iterations = 120_000;

    public void SetPassword(string password)
    {
        if (password.Length == 0) { PasswordHash = PasswordSalt = ""; return; }
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        PasswordSalt = Convert.ToBase64String(salt);
        PasswordHash = Convert.ToBase64String(Hash(password, salt));
    }

    public bool CheckPassword(string password)
    {
        if (!HasPassword) return true;
        try
        {
            byte[] expected = Convert.FromBase64String(PasswordHash);
            byte[] actual = Hash(password, Convert.FromBase64String(PasswordSalt));
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch { return false; }
    }

    private static byte[] Hash(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);

    // ------------------------------------------------------------------

    public static readonly string FilePath = Path.Combine(RuleStore.Folder, "ajustes.json");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Json) ?? new AppSettings();
        }
        catch { }
        return new AppSettings();
    }

    public void Save()
    {
        Directory.CreateDirectory(RuleStore.Folder);
        string tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, FilePath, true);
    }
}
