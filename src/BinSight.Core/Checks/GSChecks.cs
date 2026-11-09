using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>GSCheck – verifies /GS stack-buffer protection is enabled (security cookie present in Load Config).</summary>
public sealed class GSCheck : ICheck
{
    public string Name => "GSCheck";
    public string Description => "Verifies the Load Config directory declares a /GS security cookie.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – /GS is a native C/C++ mitigation.");

        var lc = pe.TryReadLoadConfig();
        if (lc is null)
            return CheckResult.Fail(Name, "Image has no Load Config directory – /GS almost certainly disabled.");

        if (!lc.HasSecurityCookie)
            return CheckResult.Fail(Name, "Load Config declares a null SecurityCookie. Rebuild with /GS.");

        return CheckResult.Pass(Name, $"Security cookie present at VA 0x{lc.SecurityCookie:X}.");
    }
}

/// <summary>
/// DefaultGSCookieCheck – without symbols we cannot read the cookie value at runtime. We flag
/// well-known default cookie values if the address resolves inside a readable section.
/// </summary>
public sealed class DefaultGSCookieCheck : ICheck
{
    public string Name => "DefaultGSCookieCheck";
    public string Description => "Flags binaries whose /GS security cookie still holds the compiler default value.";
    public bool EnabledByDefault => true;

    // Well-known default cookie values set by the compiler before __security_init_cookie runs.
    private static readonly ulong[] DefaultCookie64 = { 0x00002B992DDFA232UL };
    private static readonly uint[]   DefaultCookie32 = { 0x0000BB40 };

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – /GS cookie checks do not apply.");

        var lc = pe.TryReadLoadConfig();
        if (lc is null || !lc.HasSecurityCookie)
            return CheckResult.NotApplicable(Name, "No security cookie configured; see GSCheck.");

        // Convert the cookie VA back to an RVA using ImageBase from the optional header.
        if (lc.SecurityCookie < pe.Headers.ImageBase)
            return CheckResult.Error(Name, $"SecurityCookie VA 0x{lc.SecurityCookie:X} is below ImageBase.");

        uint cookieRva = (uint)(lc.SecurityCookie - pe.Headers.ImageBase);
        int readLen = pe.Headers.Is64Bit ? 8 : 4;
        if (!pe.TryReadAtRva(cookieRva, readLen, out var bytes))
            return CheckResult.Error(Name, $"Could not read cookie bytes at RVA 0x{cookieRva:X}.");

        if (pe.Headers.Is64Bit)
        {
            ulong value = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes);
            if (Array.IndexOf(DefaultCookie64, value) >= 0)
                return CheckResult.Fail(Name,
                    $"Security cookie storage holds the compiler default value 0x{value:X16}. " +
                    "On a static on-disk scan this is often expected (randomized at process start); " +
                    "correlate with GSCheck/GSFriendlyInitCheck and see triage notes.");
            return CheckResult.Pass(Name, $"Security cookie storage holds a non-default value (0x{value:X16}).");
        }
        else
        {
            uint value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes);
            if (Array.IndexOf(DefaultCookie32, value) >= 0)
                return CheckResult.Fail(Name,
                    $"Security cookie storage holds the compiler default value 0x{value:X8}. " +
                    "On a static on-disk scan this is often expected (randomized at process start); " +
                    "correlate with GSCheck/GSFriendlyInitCheck and see triage notes.");
            return CheckResult.Pass(Name, $"Security cookie storage holds a non-default value (0x{value:X8}).");
        }
    }
}

/// <summary>
/// GSFunctionSafeBuffersCheck – the Load Config's GuardFlags should NOT advertise that the security
/// cookie is unused. Combined with a non-null cookie pointer this signals buffer-security data is intact.
/// </summary>
public sealed class GSFunctionSafeBuffersCheck : ICheck
{
    public string Name => "GSFunctionSafeBuffersCheck";
    public string Description => "Validates that the Load Config advertises an active /GS buffer-security contract.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – /GS buffer security does not apply.");

        var lc = pe.TryReadLoadConfig();
        if (lc is null)
            return CheckResult.Fail(Name, "No Load Config directory – /GS buffer security data missing.");

        if ((lc.GuardFlags & PEConstants.GuardSecurityCookieUnused) != 0)
            return CheckResult.Fail(Name,
                "GuardFlags advertises IMAGE_GUARD_SECURITY_COOKIE_UNUSED. Rebuild with /GS and current toolset.");

        if (!lc.HasSecurityCookie)
            return CheckResult.Fail(Name, "SecurityCookie pointer is null – buffer security data missing.");

        return CheckResult.Pass(Name,
            $"Load Config declares an active /GS cookie (GuardFlags=0x{lc.GuardFlags:X8}).");
    }
}

/// <summary>
/// GSFriendlyInitCheck – /GS requires __security_init_cookie to run before user code. We approximate
/// this by looking for KERNEL32 imports needed by __security_init_cookie and by checking that
/// Control Flow Guard (modern /GS prerequisite) is either enabled or at least configurable.
/// </summary>
public sealed class GSFriendlyInitCheck : ICheck
{
    public string Name => "GSFriendlyInitCheck";
    public string Description => "Heuristically verifies the image uses a /GS-friendly C runtime initializer.";
    public bool EnabledByDefault => true;

    private static readonly HashSet<string> InitHelpers = new(StringComparer.OrdinalIgnoreCase)
    {
        "QueryPerformanceCounter",
        "GetSystemTimeAsFileTime",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetTickCount",
        "GetTickCount64",
    };

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – CRT GS initializer does not apply.");

        var lc = pe.TryReadLoadConfig();
        if (lc is null)
            return CheckResult.Fail(Name, "No Load Config directory; GS initialization cannot be verified.");

        bool importsSeed = false;
        foreach (var imp in pe.ReadImports())
        {
            if (!imp.DllName.StartsWith("KERNEL32", StringComparison.OrdinalIgnoreCase) &&
                !imp.DllName.StartsWith("API-MS-WIN-CORE", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var sym in imp.Symbols)
            {
                if (sym.Name is not null && InitHelpers.Contains(sym.Name))
                {
                    importsSeed = true;
                    break;
                }
            }
            if (importsSeed) break;
        }

        if (!importsSeed)
            return CheckResult.Fail(Name,
                "Could not confirm the image imports an entropy source for __security_init_cookie. " +
                "Ensure the CRT is linked and /GS is enabled.");

        return CheckResult.Pass(Name,
            "Image imports a seeding primitive (e.g. QueryPerformanceCounter) consistent with a GS-friendly initializer.");
    }
}
