using BinSight.Core.Checks;

namespace BinSight.Core.Formats;

/// <summary>ELF / Mach-O mitigation checks analogous to PE ASLR/DEP/GS/CFG-era controls.</summary>
public static class UnixChecks
{
    public static IReadOnlyList<CheckResult> RunElf(ElfFile elf)
    {
        var results = new List<CheckResult>();

        results.Add(elf.IsPie
            ? CheckResult.Pass("ElfPieCheck", "ELF is ET_DYN (PIE) — ASLR-capable load.")
            : CheckResult.Fail("ElfPieCheck", "ELF is not PIE (ET_EXEC). Link with -fPIE -pie for ASLR."));

        results.Add(!elf.HasExecutableStack
            ? CheckResult.Pass("ElfNxCheck", "PT_GNU_STACK is non-executable (NX stack).")
            : CheckResult.Fail("ElfNxCheck", "PT_GNU_STACK allows an executable stack. Link with -z noexecstack."));

        if (elf.HasGnuRelro && elf.HasBindNow)
            results.Add(CheckResult.Pass("ElfRelroCheck", "Full RELRO (PT_GNU_RELRO + BIND_NOW)."));
        else if (elf.HasGnuRelro)
            results.Add(CheckResult.Fail("ElfRelroCheck", "Partial RELRO only (PT_GNU_RELRO without BIND_NOW). Link with -z relro -z now."));
        else
            results.Add(CheckResult.Fail("ElfRelroCheck", "No PT_GNU_RELRO. Link with -z relro -z now for full RELRO."));

        results.Add(elf.HasStackCanary
            ? CheckResult.Pass("ElfStackCanaryCheck", "Stack canary helpers present (__stack_chk_*).")
            : CheckResult.Fail("ElfStackCanaryCheck", "No stack canary symbols found. Compile with -fstack-protector-strong."));

        results.Add(elf.HasFortify
            ? CheckResult.Pass("ElfFortifyCheck", "Fortify source helpers detected (*_chk).")
            : CheckResult.Pass("ElfFortifyCheck",
                "No obvious Fortify *_chk helpers in the image (may still be present with different linkage). Build with -D_FORTIFY_SOURCE=2 for stronger checks."));

        return results;
    }

    public static IReadOnlyList<CheckResult> RunMachO(MachOFile macho)
    {
        var results = new List<CheckResult>();

        results.Add(macho.IsPie
            ? CheckResult.Pass("MachOPieCheck", "MH_PIE is set — ASLR-capable Mach-O.")
            : CheckResult.Fail("MachOPieCheck", "MH_PIE is clear. Enable PIE for ASLR."));

        results.Add(!macho.AllowsStackExecution
            ? CheckResult.Pass("MachONxCheck", "MH_ALLOW_STACK_EXECUTION is clear (NX stack policy).")
            : CheckResult.Fail("MachONxCheck", "MH_ALLOW_STACK_EXECUTION is set — executable stack allowed."));

        results.Add(macho.HasStackCanary
            ? CheckResult.Pass("MachOStackCanaryCheck", "Stack canary helpers present (__stack_chk_*).")
            : CheckResult.Fail("MachOStackCanaryCheck", "No stack canary symbols found. Build with -fstack-protector."));

        results.Add(macho.HasCodeSignature
            ? CheckResult.Pass("MachOCodeSignatureCheck", "Code signature load command / blob indicators present.")
            : CheckResult.Fail("MachOCodeSignatureCheck", "No code signature indicators found. Sign with codesign for integrity on macOS."));

        return results;
    }
}
