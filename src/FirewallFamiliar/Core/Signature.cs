using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallFamiliar.Core;

public enum SignatureStatus
{
    /// <summary>Todavía no se ha comprobado.</summary>
    Pendiente,
    /// <summary>Firma válida (dentro del archivo o en un catálogo de Windows).</summary>
    Valida,
    /// <summary>El archivo no lleva firma digital.</summary>
    SinFirma,
    /// <summary>Lleva firma pero no es válida: archivo modificado, certificado no fiable o caducado.</summary>
    NoValida,
    /// <summary>No se pudo comprobar (sin permiso, archivo borrado...).</summary>
    Desconocida
}

public sealed record SignatureInfo(SignatureStatus Status, string Signer, string Detail)
{
    public static readonly SignatureInfo Pending = new(SignatureStatus.Pendiente, "", "");

    /// <summary>Texto corto para la columna "Firma".</summary>
    public string Short => Status switch
    {
        SignatureStatus.Valida => Signer.Length > 0 ? "✔ " + Signer : "✔ Firmado",
        SignatureStatus.SinFirma => "✖ Sin firma",
        SignatureStatus.NoValida => "⚠ Firma NO válida",
        SignatureStatus.Desconocida => "?",
        _ => ""
    };

    /// <summary>Explicación para la ficha de detalles.</summary>
    public string Long => Status switch
    {
        SignatureStatus.Valida => $"Firma digital válida de {(Signer.Length > 0 ? Signer : "un fabricante reconocido")}{Detail}. El archivo no ha sido modificado.",
        SignatureStatus.SinFirma => "Sin firma digital. No se sabe quién lo ha hecho; muchos programas pequeños o caseros no la llevan, pero los virus tampoco.",
        SignatureStatus.NoValida => $"La firma NO es válida ({Detail}). El archivo puede haber sido modificado o el certificado no es de confianza.",
        SignatureStatus.Desconocida => "No se ha podido comprobar la firma" + (Detail.Length > 0 ? $" ({Detail})." : "."),
        _ => "Comprobando..."
    };
}

/// <summary>
/// Comprueba de verdad la firma digital de los programas (como hace Windows al instalar algo):
/// primero la firma dentro del .exe y, si no tiene, los catálogos de Windows, que es donde
/// van firmados casi todos los archivos del propio sistema. No consulta Internet.
/// </summary>
public static class Signature
{
    private static readonly ConcurrentDictionary<string, (DateTime Stamp, SignatureInfo Info)> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, byte> Queued = new(StringComparer.OrdinalIgnoreCase);
    private static readonly BlockingCollection<string> Work = new();
    private static int _started;

    /// <summary>Se lanza cuando termina la comprobación de un archivo (desde otro hilo).</summary>
    public static event Action<string, SignatureInfo>? Checked;

    /// <summary>Devuelve el resultado si ya se conoce; si no, lo pide en segundo plano y devuelve "Pendiente".</summary>
    public static SignatureInfo Get(string path)
    {
        if (string.IsNullOrEmpty(path)) return new SignatureInfo(SignatureStatus.Desconocida, "", "sin ruta");
        if (string.Equals(path, "System", StringComparison.OrdinalIgnoreCase))
            return new SignatureInfo(SignatureStatus.Valida, "Microsoft Windows", "");
        if (string.Equals(path, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
            return new SignatureInfo(SignatureStatus.Valida, "Firewall Familiar (este programa)", "");
        if (Cache.TryGetValue(path, out var hit)) return hit.Info;
        if (Queued.TryAdd(path, 0))
        {
            StartWorker();
            Work.Add(path);
        }
        return SignatureInfo.Pending;
    }

    /// <summary>Comprobación inmediata (para las fichas de detalles).</summary>
    public static SignatureInfo CheckNow(string path)
    {
        if (string.Equals(path, "System", StringComparison.OrdinalIgnoreCase))
            return new SignatureInfo(SignatureStatus.Valida, "Microsoft Windows", "");
        DateTime stamp = Stamp(path);
        if (Cache.TryGetValue(path, out var hit) && hit.Stamp == stamp) return hit.Info;
        var info = Verify(path);
        Cache[path] = (stamp, info);
        return info;
    }

    private static DateTime Stamp(string path)
    {
        try { return File.GetLastWriteTimeUtc(path); } catch { return DateTime.MinValue; }
    }

    private static void StartWorker()
    {
        if (Interlocked.Exchange(ref _started, 1) == 1) return;
        var t = new Thread(() =>
        {
            foreach (var path in Work.GetConsumingEnumerable())
            {
                SignatureInfo info;
                try { info = Verify(path); }
                catch (Exception ex) { info = new SignatureInfo(SignatureStatus.Desconocida, "", ex.Message); }
                Cache[path] = (Stamp(path), info);
                Queued.TryRemove(path, out _);
                try { Checked?.Invoke(path, info); } catch { }
            }
        })
        { IsBackground = true, Name = "Comprobar firmas", Priority = ThreadPriority.BelowNormal };
        t.Start();
    }

    // =====================================================================
    // WinVerifyTrust
    // =====================================================================

    private static SignatureInfo Verify(string path)
    {
        if (!File.Exists(path)) return new SignatureInfo(SignatureStatus.Desconocida, "", "no se encuentra el archivo");

        // 1) Firma dentro del archivo
        uint result = VerifyEmbedded(path, out string signer);
        if (result == 0) return new SignatureInfo(SignatureStatus.Valida, signer, "");
        if (result != TRUST_E_NOSIGNATURE && result != TRUST_E_SUBJECT_FORM_UNKNOWN && result != TRUST_E_PROVIDER_UNKNOWN)
            return new SignatureInfo(SignatureStatus.NoValida, signer, Explain(result));

        // 2) Catálogos de Windows
        uint cat = VerifyCatalog(path, out signer);
        if (cat == 0) return new SignatureInfo(SignatureStatus.Valida, signer, " (catálogo de Windows)");
        if (cat != NOT_IN_CATALOG && cat != TRUST_E_NOSIGNATURE)
            return new SignatureInfo(SignatureStatus.NoValida, signer, Explain(cat));

        // 3) Apps de la Microsoft Store: la firma va en el paquete (AppxSignature.p7x), no en cada .exe
        if (PackageSigner(path) is { } pkg)
            return new SignatureInfo(SignatureStatus.Valida, pkg, " (paquete de la Microsoft Store)");
        return new SignatureInfo(SignatureStatus.SinFirma, "", "");
    }

    /// <summary>
    /// Si el archivo es de una app instalada desde la Tienda (C:\Program Files\WindowsApps\...),
    /// devuelve quién firmó el paquete. Esa carpeta solo la puede tocar Windows.
    /// </summary>
    private static string? PackageSigner(string path)
    {
        const string marker = @"\WindowsApps\";
        int i = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;
        int start = i + marker.Length;
        int end = path.IndexOf('\\', start);
        if (end < 0) return null;
        string sigFile = Path.Combine(path[..end], "AppxSignature.p7x");
        try
        {
            if (!File.Exists(sigFile)) return null;
            byte[] data = File.ReadAllBytes(sigFile);
            // El archivo empieza por "PKCX" y luego va la firma PKCS#7
            if (data.Length < 8 || data[0] != 'P' || data[1] != 'K' || data[2] != 'C' || data[3] != 'X') return null;
            var cms = new System.Security.Cryptography.Pkcs.SignedCms();
            cms.Decode(data.AsSpan(4).ToArray());
            cms.CheckSignature(true); // firma bien formada (sin comprobar la cadena por Internet)
            var cert = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].Certificate : null;
            if (cert == null) return null;
            string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrEmpty(cn) ? cert.Subject : cn;
        }
        catch { return null; }
    }

    private static string Explain(uint code) => code switch
    {
        TRUST_E_BAD_DIGEST => "el archivo ha sido modificado después de firmarlo",
        CERT_E_EXPIRED => "el certificado ha caducado",
        CERT_E_UNTRUSTEDROOT => "certificado de un emisor no reconocido",
        CERT_E_CHAINING => "no se puede comprobar la cadena del certificado",
        TRUST_E_EXPLICIT_DISTRUST => "certificado marcado como NO fiable",
        CERT_E_REVOKED => "certificado revocado",
        TRUST_E_SUBJECT_NOT_TRUSTED => "no es de confianza",
        _ => $"código 0x{code:X8}"
    };

    private static unsafe uint VerifyEmbedded(string path, out string signer)
    {
        signer = "";
        fixed (char* p = path)
        {
            var file = new WINTRUST_FILE_INFO { cbStruct = (uint)sizeof(WINTRUST_FILE_INFO), pcwszFilePath = (IntPtr)p };
            var data = NewData(WTD_CHOICE_FILE, (IntPtr)(&file));
            return Run(ref data, out signer);
        }
    }

    private static uint VerifyCatalog(string path, out string signer)
    {
        // Los catálogos modernos usan SHA256; los antiguos, SHA1 (algoritmo nulo).
        uint r = VerifyCatalog(path, "SHA256", out signer);
        if (r == NOT_IN_CATALOG) r = VerifyCatalog(path, null, out signer);
        return r;
    }

    private static unsafe uint VerifyCatalog(string path, string? algorithm, out string signer)
    {
        signer = "";
        IntPtr admin = IntPtr.Zero, catInfo = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) return NOT_IN_CATALOG;

            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle.DangerousGetHandle(), ref size, null, 0);
            if (size == 0 || size > 256) return NOT_IN_CATALOG;
            byte* hash = stackalloc byte[(int)size];
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle.DangerousGetHandle(), ref size, hash, 0))
                return NOT_IN_CATALOG;

            catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
            if (catInfo == IntPtr.Zero) return NOT_IN_CATALOG;

            var ci = new CATALOG_INFO { cbStruct = (uint)sizeof(CATALOG_INFO) };
            if (!CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) return NOT_IN_CATALOG;

            string tag = Convert.ToHexString(new ReadOnlySpan<byte>(hash, (int)size));
            fixed (char* pPath = path)
            fixed (char* pTag = tag)
            {
                var catalog = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)sizeof(WINTRUST_CATALOG_INFO),
                    pcwszCatalogFilePath = (IntPtr)ci.wszCatalogFile,
                    pcwszMemberTag = (IntPtr)pTag,
                    pcwszMemberFilePath = (IntPtr)pPath,
                    pbCalculatedFileHash = (IntPtr)hash,
                    cbCalculatedFileHash = size,
                    hCatAdmin = admin
                };
                var data = NewData(WTD_CHOICE_CATALOG, (IntPtr)(&catalog));
                return Run(ref data, out signer);
            }
        }
        catch
        {
            return NOT_IN_CATALOG;
        }
        finally
        {
            if (catInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catInfo, 0);
            if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
        }
    }

    private static unsafe WINTRUST_DATA NewData(uint choice, IntPtr info) => new()
    {
        cbStruct = (uint)sizeof(WINTRUST_DATA),
        dwUIChoice = WTD_UI_NONE,
        fdwRevocationChecks = WTD_REVOKE_NONE,
        dwUnionChoice = choice,
        pInfo = info,
        dwStateAction = WTD_STATEACTION_VERIFY,
        // Sin Internet: no se descargan listas de revocación (sería lento y sin conexión fallaría)
        dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
    };

    /// <summary>Ejecuta la comprobación, saca el nombre del firmante y libera el estado.</summary>
    private static unsafe uint Run(ref WINTRUST_DATA data, out string signer)
    {
        signer = "";
        Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        uint result = (uint)WinVerifyTrust(new IntPtr(-1) /* INVALID_HANDLE_VALUE: sin ventanas */, ref action, ref data);
        try
        {
            if (data.hWVTStateData != IntPtr.Zero) signer = SignerName(data.hWVTStateData);
        }
        catch { }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
        return result;
    }

    private static unsafe string SignerName(IntPtr state)
    {
        IntPtr prov = WTHelperProvDataFromStateData(state);
        if (prov == IntPtr.Zero) return "";
        IntPtr sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if (sgnr == IntPtr.Zero) return "";
        IntPtr provCert = WTHelperGetProvCertFromChain(sgnr, 0);
        if (provCert == IntPtr.Zero) return "";
        // CRYPT_PROVIDER_CERT: { DWORD cbStruct; PCCERT_CONTEXT pCert; ... }
        IntPtr certContext = *(IntPtr*)((byte*)provCert + IntPtr.Size);
        if (certContext == IntPtr.Zero) return "";
        using var cert = new X509Certificate2(certContext);
        string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
        return string.IsNullOrEmpty(cn) ? cert.Subject : cn;
    }

    // =====================================================================
    // Declaraciones de wintrust.dll
    // =====================================================================

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
    private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
    private const uint TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004;
    private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
    private const uint TRUST_E_BAD_DIGEST = 0x80096010;
    private const uint CERT_E_EXPIRED = 0x800B0101;
    private const uint CERT_E_CHAINING = 0x800B010A;
    private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
    private const uint CERT_E_REVOKED = 0x800B010C;
    /// <summary>Valor propio: el archivo no aparece en ningún catálogo.</summary>
    private const uint NOT_IN_CATALOG = 0xFFFFFFFF;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private unsafe struct CATALOG_INFO
    {
        public uint cbStruct;
        public fixed char wszCatalogFile[260];
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte* pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern unsafe IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte* pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);
}
