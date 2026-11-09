using System.Runtime.InteropServices;

namespace BinSight.Core.PE;

/// <summary>Result of a Windows Authenticode verification attempt.</summary>
public sealed record AuthenticodeVerifyResult(bool Trusted, string Message, IReadOnlyList<string>? Details = null);

/// <summary>
/// Thin WinVerifyTrust wrapper. Only functional on Windows; callers should gate with
/// <see cref="OperatingSystem.IsWindows"/>.
/// </summary>
public static class AuthenticodeVerifier
{
    public static AuthenticodeVerifyResult Verify(string filePath)
    {
        if (!OperatingSystem.IsWindows())
            return new AuthenticodeVerifyResult(false, "Not running on Windows.");

        Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var trustData = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            dwStateAction = WTD_STATEACTION_IGNORE,
            dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL,
        };

        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            trustData.pFile = pFile;

            int hr = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            return hr switch
            {
                0 => new AuthenticodeVerifyResult(true,
                    "WinVerifyTrust: signature is trusted.",
                    new[] { $"path={filePath}", "hr=0 (TRUST_E_OK)" }),
                unchecked((int)0x800B0100) => new AuthenticodeVerifyResult(false,
                    "WinVerifyTrust: no signature found (TRUST_E_NOSIGNATURE).",
                    new[] { $"hr=0x{hr:X8}" }),
                unchecked((int)0x800B0101) => new AuthenticodeVerifyResult(false,
                    "WinVerifyTrust: certificate expired (CERT_E_EXPIRED).",
                    new[] { $"hr=0x{hr:X8}" }),
                unchecked((int)0x800B0109) => new AuthenticodeVerifyResult(false,
                    "WinVerifyTrust: root/CA not trusted (CERT_E_UNTRUSTEDROOT).",
                    new[] { $"hr=0x{hr:X8}" }),
                unchecked((int)0x80096010) => new AuthenticodeVerifyResult(false,
                    "WinVerifyTrust: signature invalid / file tampered (TRUST_E_BAD_DIGEST).",
                    new[] { $"hr=0x{hr:X8}" }),
                _ => new AuthenticodeVerifyResult(false,
                    $"WinVerifyTrust: verification failed (hr=0x{hr:X8}).",
                    new[] { $"hr=0x{hr:X8}" }),
            };
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
        }
    }

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_IGNORE = 0;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
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
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
}
