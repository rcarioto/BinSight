using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>
/// ExtendedMitigationsCheck – post-BinScope flags: hotpatch compatibility, EH continuation,
/// and presence of volatile/Spectre-related debug metadata.
/// </summary>
public sealed class ExtendedMitigationsCheck : ICheck
{
    public string Name => "ExtendedMitigationsCheck";
    public string Description => "Reports CET-adjacent extended flags, hotpatch compatibility, EH continuation, and volatile metadata.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed image – extended native mitigation bits are hosted by the runtime.");

        var details = new List<string>();
        uint ex = pe.TryReadExtendedDllCharacteristics();
        var lc = pe.TryReadLoadConfig();

        bool hotpatch = (ex & PEConstants.ExDllCharHotpatchCompatible) != 0;
        bool ehCont = lc is not null && (lc.GuardFlags & PEConstants.GuardEhContinuationTablePresent) != 0;
        bool xfg = lc is not null && (lc.GuardFlags & PEConstants.GuardXfgEnabled) != 0;
        bool volatileMeta = pe.ReadDebugEntries().Any(d =>
            d.Type == PEConstants.DebugTypeExtended ||
            d.TypeName.Contains("VOLATILE", StringComparison.OrdinalIgnoreCase));

        // Also look for a .voltbl / .gfids style section name hint.
        bool voltSection = pe.Sections.Any(s =>
            s.Name.Contains("volt", StringComparison.OrdinalIgnoreCase) ||
            s.Name.Equals(".gfids", StringComparison.OrdinalIgnoreCase));

        details.Add($"ExtendedDllCharacteristics=0x{ex:X}");
        details.Add($"HotpatchCompatible={hotpatch}");
        details.Add($"EHContinuationTable={(ehCont ? "present" : "absent")}");
        details.Add($"XFG={(xfg ? "enabled" : "absent")}");
        details.Add($"VolatileOrSpectreMetadata={(volatileMeta || voltSection)}");

        if (pe.Headers.Machine is PEConstants.MachineArm64 or PEConstants.MachineArm)
            details.Add($"Architecture note: {pe.Headers.MachineName} — verify CFG/PAC/BTI expectations for your deployment OS.");

        // Informational: pass if at least CFG-era binary; fail only when modern x64 lacks all extended signals
        // and CET was also absent — keep soft: Pass with guidance unless completely barren on a modern 64-bit native.
        bool modern64 = pe.Headers.Is64Bit && pe.Headers.MajorLinkerVersion >= 14;
        if (modern64 && !hotpatch && !ehCont && !xfg && !volatileMeta && !voltSection && ex == 0)
        {
            return CheckResult.Fail(Name,
                "No extended mitigation metadata detected (hotpatch / EH continuation / XFG / volatile). " +
                "Consider a current toolset with /CETCOMPAT, /guard:ehcont, and up-to-date Spectre mitigations.",
                details);
        }

        return CheckResult.Pass(Name,
            "Extended mitigation metadata surveyed (see details). Absence of optional bits is not always a defect.",
            details);
    }
}

/// <summary>
/// DangerousApiCheck – heuristic import review for APIs commonly abused or indicative of risky patterns.
/// Informational by nature; Fail when high-severity combinations are present.
/// </summary>
public sealed class DangerousApiCheck : ICheck
{
    public string Name => "DangerousApiCheck";
    public string Description => "Flags imported APIs often associated with memory RWX, dynamic code, or legacy crypto (heuristic).";
    public bool EnabledByDefault => true;

    private static readonly HashSet<string> High = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory",
        "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "SetWindowsHookExA", "SetWindowsHookExW",
    };

    private static readonly HashSet<string> Medium = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory",
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
        "WinExec", "ShellExecuteA", "ShellExecuteW", "system",
        "CryptEncrypt", "CryptDecrypt", // legacy crypto surface; CNG preferred
    };

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed image – native import heuristics do not apply.");

        var highHits = new List<string>();
        var mediumHits = new List<string>();

        foreach (var imp in pe.ReadImports())
        {
            foreach (var sym in imp.Symbols)
            {
                if (sym.Name is null) continue;
                if (High.Contains(sym.Name))
                    highHits.Add($"{imp.DllName}!{sym.Name}");
                else if (Medium.Contains(sym.Name))
                    mediumHits.Add($"{imp.DllName}!{sym.Name}");
            }
        }

        var details = new List<string>();
        if (highHits.Count > 0)
        {
            details.Add("High-interest imports:");
            details.AddRange(highHits.Distinct().OrderBy(s => s).Select(s => "  " + s));
        }
        if (mediumHits.Count > 0)
        {
            details.Add("Medium-interest imports:");
            details.AddRange(mediumHits.Distinct().OrderBy(s => s).Take(40).Select(s => "  " + s));
            if (mediumHits.Distinct().Count() > 40)
                details.Add($"  … and {mediumHits.Distinct().Count() - 40} more");
        }

        if (highHits.Count > 0)
            return CheckResult.Fail(Name,
                $"Found {highHits.Distinct().Count()} high-interest API import(s) often used in process injection / RWX flows. " +
                "Review for legitimacy (runtime hosts/JITs/installers often need VirtualProtect — see triage notes).",
                details);

        if (mediumHits.Count > 0)
            return CheckResult.Pass(Name,
                $"No high-interest injection APIs; {mediumHits.Distinct().Count()} medium-interest import(s) noted for review.",
                details);

        return CheckResult.Pass(Name, "No high/medium-interest dangerous-API import patterns detected.");
    }
}

/// <summary>
/// AuthenticodeVerifyCheck – on Windows, calls WinVerifyTrust when a cert table exists.
/// </summary>
public sealed class AuthenticodeVerifyCheck : ICheck
{
    public string Name => "AuthenticodeVerifyCheck";
    public string Description => "On Windows, cryptographically verifies Authenticode via WinVerifyTrust when a signature is present.";
    public bool EnabledByDefault => false; // opt-in / audit; requires Windows

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (!pe.HasAuthenticodeCertificateTable)
            return CheckResult.Fail(Name, "No Authenticode certificate table to verify.");

        if (!OperatingSystem.IsWindows())
            return CheckResult.NotApplicable(Name,
                "Authenticode cryptographic verification requires Windows (WinVerifyTrust). Certificate table is present; verify on a Windows host or use signtool.");

        try
        {
            var result = AuthenticodeVerifier.Verify(pe.FilePath);
            return result.Trusted
                ? CheckResult.Pass(Name, result.Message, result.Details)
                : CheckResult.Fail(Name, result.Message, result.Details);
        }
        catch (Exception ex)
        {
            return CheckResult.Error(Name, $"WinVerifyTrust failed: {ex.Message}");
        }
    }
}
