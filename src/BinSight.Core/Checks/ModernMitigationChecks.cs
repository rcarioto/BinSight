using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>
/// CFGCheck – Control Flow Guard (/guard:cf). Post-2014 SDL staple that BinScope 2014
/// only partially covered via the optional FunctionPointersCheck.
/// </summary>
public sealed class CFGCheck : ICheck
{
    public string Name => "CFGCheck";
    public string Description => "Verifies Control Flow Guard (/GUARD:CF) is enabled and backed by Load Config metadata.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – CFG is enforced by the CLR / RyuJIT, not PE CFG bits.");

        // CFG landed with VS2015 / Windows 8.1-era tooling. Don't fail WinXP-era binaries for lacking it.
        var era = BinaryEra.Classify(pe);
        if (era.IsLegacyTooling && pe.Headers.MajorLinkerVersion < 14)
            return CheckResult.NotApplicable(Name,
                $"Binary era is '{era.Label}' (pre-CFG toolchain). CFG requires VS2015+ (/GUARD:CF).");

        bool dllFlag = (pe.Headers.DllCharacteristics & PEConstants.DllCharGuardCf) != 0;
        var lc = pe.TryReadLoadConfig();

        if (dllFlag && lc is not null && lc.HasControlFlowGuard)
            return CheckResult.Pass(Name,
                $"Control Flow Guard enabled (DllCharacteristics GUARD_CF + GuardFlags=0x{lc.GuardFlags:X8}).");

        if (dllFlag && (lc is null || !lc.HasControlFlowGuard))
            return CheckResult.Fail(Name,
                "IMAGE_DLLCHARACTERISTICS_GUARD_CF is set but Load Config does not advertise an instrumented CF check function.");

        if (!dllFlag && lc is not null && lc.HasControlFlowGuard)
            return CheckResult.Fail(Name,
                "Load Config advertises CFG instrumentation but DllCharacteristics GUARD_CF is clear.");

        return CheckResult.Fail(Name,
            "Control Flow Guard is not enabled. Relink with /GUARD:CF (VS2015+).");
    }
}

/// <summary>
/// CETCheck – Hardware-enforced stack protection (/CETCOMPAT), introduced with Windows 10
/// 20H1 / Intel CET and invisible to BinScope 2014.
/// </summary>
public sealed class CETCheck : ICheck
{
    public string Name => "CETCheck";
    public string Description => "Verifies IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT (/CETCOMPAT) for hardware shadow stacks.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – CET compatibility is hosted by the runtime.");

        // CET shadow stacks are an x64 (and some ARM64) feature; 32-bit images are N/A.
        if (pe.Headers.Is32Bit && pe.Headers.Machine == PEConstants.MachineI386)
            return CheckResult.NotApplicable(Name, "CET shadow-stack compatibility applies to 64-bit images.");

        var era = BinaryEra.Classify(pe);
        if (era.IsLegacyTooling || pe.Headers.MajorLinkerVersion < 14)
            return CheckResult.NotApplicable(Name,
                $"Binary era is '{era.Label}'. /CETCOMPAT requires VS2019 16.7+ and Win10 20H1+.");

        uint ex = pe.TryReadExtendedDllCharacteristics();
        bool cet = (ex & PEConstants.ExDllCharCetCompat) != 0;
        bool strict = (ex & PEConstants.ExDllCharCetCompatStrictMode) != 0;

        if (cet)
        {
            string mode = strict ? "strict" : "compatible";
            return CheckResult.Pass(Name,
                $"Image is marked /CETCOMPAT ({mode} mode). ExtendedDllCharacteristics=0x{ex:X}");
        }

        if (ex == 0)
            return CheckResult.Fail(Name,
                "No extended DLL characteristics (CET) debug entry. Relink with /CETCOMPAT (VS2019 16.7+) " +
                "when you own this PE's link; runtime/apphost stubs you do not rebuild may not be actionable.");

        return CheckResult.Fail(Name,
            $"Extended DLL characteristics present (0x{ex:X}) but CET_COMPAT bit is clear. Relink with /CETCOMPAT " +
            "when you own this PE's link; see triage notes for vendor/host stubs.");
    }
}

/// <summary>
/// RelocsStrippedCheck – DYNAMICBASE is ineffective if relocations were stripped.
/// </summary>
public sealed class RelocsStrippedCheck : ICheck
{
    public string Name => "RelocsStrippedCheck";
    public string Description => "Fails if IMAGE_FILE_RELOCS_STRIPPED is set (breaks ASLR even when /DYNAMICBASE is present).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        bool stripped = pe.Headers.RelocsStripped;
        bool hasRelocDir = pe.Headers.HasRelocations;
        bool dynamic = (pe.Headers.DllCharacteristics & PEConstants.DllCharDynamicBase) != 0;

        if (stripped)
            return CheckResult.Fail(Name,
                "IMAGE_FILE_RELOCS_STRIPPED is set – the loader cannot rebase this image, so ASLR cannot work.");

        if (dynamic && !hasRelocDir && !pe.IsManaged)
            return CheckResult.Fail(Name,
                "/DYNAMICBASE is set but the base relocation directory is empty – ASLR will not be effective.");

        if (!hasRelocDir && !pe.IsManaged)
            return CheckResult.Fail(Name,
                "No base relocation directory. Prefer linking without /FIXED so ASLR can rebase the image.");

        return CheckResult.Pass(Name,
            pe.IsManaged
                ? "Managed image – PE relocation directory may be minimal; CLR handles layout."
                : "Relocations present and IMAGE_FILE_RELOCS_STRIPPED is clear.");
    }
}

/// <summary>
/// AuthenticodeCheck – reports whether an Authenticode certificate table is embedded.
/// Does not cryptographically validate the chain (that requires WinVerifyTrust on Windows).
/// </summary>
public sealed class AuthenticodeCheck : ICheck
{
    public string Name => "AuthenticodeCheck";
    public string Description => "Reports whether an Authenticode certificate table is present (presence only; not chain validation).";
    // Opt-in: many internal/CI artifacts are unsigned; enable for release / audit scans.
    public bool EnabledByDefault => false;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (!pe.HasAuthenticodeCertificateTable)
            return CheckResult.Fail(Name,
                "No Authenticode certificate table. Sign the binary (signtool / Azure Signing) for integrity and identity.");

        var info = pe.TryReadAuthenticodeInfo();
        if (info is null)
            return CheckResult.Error(Name, "Certificate table directory is non-empty but the WIN_CERTIFICATE header could not be parsed.");

        return CheckResult.Pass(Name,
            $"Authenticode certificate table present (revision=0x{info.Revision:X}, type={info.CertificateType}, blob={info.BlobSize} bytes). " +
            "Note: BinSight checks presence only; use signtool verify / WinVerifyTrust for chain validation.");
    }
}

/// <summary>
/// DelayLoadCheck – when delay-load imports exist, require GuardFlags delay-load IAT protection.
/// </summary>
public sealed class DelayLoadCheck : ICheck
{
    public string Name => "DelayLoadCheck";
    public string Description => "When delay-load imports exist, verifies IMAGE_GUARD_PROTECT_DELAYLOAD_IAT (/DELAYLOAD with guarded IAT).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        var delay = pe.ReadDelayLoadDllNames();
        if (delay.Count == 0)
            return CheckResult.NotApplicable(Name, "Image has no delay-load imports.");

        var lc = pe.TryReadLoadConfig();
        if (lc is null)
            return CheckResult.Fail(Name,
                $"Image delay-loads {delay.Count} DLL(s) but has no Load Config to protect the delay-load IAT.");

        bool protectedIat = (lc.GuardFlags & PEConstants.GuardProtectDelayLoadIat) != 0;
        bool ownSection = (lc.GuardFlags & PEConstants.GuardDelayLoadIatInOwnSection) != 0;

        if (protectedIat)
        {
            var details = delay.Select(d => $"delay-loads {d}").ToList();
            if (ownSection) details.Add("Delay-load IAT is in its own section.");
            return CheckResult.Pass(Name,
                "Delay-load IAT protection is enabled (IMAGE_GUARD_PROTECT_DELAYLOAD_IAT).", details);
        }

        return CheckResult.Fail(Name,
            "Delay-load imports are present but IMAGE_GUARD_PROTECT_DELAYLOAD_IAT is not set. " +
            "Link with a current toolset and /DELAYLOAD so the IAT is read-only after bind.",
            delay.Select(d => $"delay-loads {d}").ToList());
    }
}

/// <summary>
/// ManifestUACCheck – inspects the embedded SxS manifest for requestedExecutionLevel.
/// </summary>
public sealed class ManifestUACCheck : ICheck
{
    public string Name => "ManifestUACCheck";
    public string Description => "Verifies EXEs declare a requestedExecutionLevel in their embedded manifest (UAC awareness).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.Headers.IsDll)
            return CheckResult.NotApplicable(Name, "DLLs are not required to declare a UAC execution level.");

        var info = pe.TryReadManifestSecurity();
        if (info is null)
            return CheckResult.Fail(Name,
                "No embedded application manifest (RT_MANIFEST). Add a UAC-aware manifest with requestedExecutionLevel.");

        if (string.IsNullOrWhiteSpace(info.RequestedExecutionLevel))
            return CheckResult.Fail(Name,
                "Embedded manifest found but requestedExecutionLevel is missing.");

        string level = info.RequestedExecutionLevel;
        bool asInvoker = level.Equals("asInvoker", StringComparison.OrdinalIgnoreCase);
        bool highest = level.Equals("highestAvailable", StringComparison.OrdinalIgnoreCase);
        bool requireAdmin = level.Equals("requireAdministrator", StringComparison.OrdinalIgnoreCase);

        var details = new List<string>
        {
            $"requestedExecutionLevel={level}",
            $"uiAccess={info.UiAccess ?? "unspecified"}",
            $"dpiAwareDeclared={info.DpiAwareDeclared}",
        };

        if (requireAdmin)
            return CheckResult.Pass(Name,
                "Manifest declares requireAdministrator. Ensure this elevation is intentional.", details);

        if (asInvoker || highest)
            return CheckResult.Pass(Name,
                $"Manifest declares UAC level '{level}'.", details);

        return CheckResult.Fail(Name,
            $"Unrecognized requestedExecutionLevel '{level}'.", details);
    }
}

/// <summary>
/// ForceIntegrityCheck – IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (code integrity enforced).
/// Useful for drivers / protected processes; opt-in for general apps.
/// </summary>
public sealed class ForceIntegrityCheck : ICheck
{
    public string Name => "ForceIntegrityCheck";
    public string Description => "Verifies IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (opt-in; common for drivers).";
    public bool EnabledByDefault => false;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        bool fi = (pe.Headers.DllCharacteristics & PEConstants.DllCharForceIntegrity) != 0;
        return fi
            ? CheckResult.Pass(Name, "Image is marked FORCE_INTEGRITY.")
            : CheckResult.Fail(Name, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY is not set.");
    }
}
