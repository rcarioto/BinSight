using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>SharedSectionCheck – fails if any section is both writable and shared.</summary>
public sealed class SharedSectionCheck : ICheck
{
    public string Name => "SharedSectionCheck";
    public string Description => "Fails if the image contains a section that is both writable and shared (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_SHARED).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        var offenders = pe.Sections.Where(s => s.IsShared && s.IsWritable).ToList();
        if (offenders.Count == 0)
        {
            return CheckResult.Pass(Name, "No writable-and-shared sections found.");
        }
        var details = offenders.Select(FormatSection).ToList();
        return CheckResult.Fail(Name, $"Found {offenders.Count} writable-and-shared section(s).", details);
    }

    private static string FormatSection(SectionHeader s) =>
        $"{s.Name}: characteristics=0x{s.Characteristics:X8} (W={s.IsWritable}, X={s.IsExecutable}, S={s.IsShared})";
}

/// <summary>WXCheck – fails if any section is both writable and executable (W^X violation).</summary>
public sealed class WXCheck : ICheck
{
    public string Name => "WXCheck";
    public string Description => "Fails if the image contains a section that is both writable and executable (W^X violation).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        var offenders = pe.Sections.Where(s => s.IsExecutable && s.IsWritable).ToList();
        if (offenders.Count == 0)
            return CheckResult.Pass(Name, "No writable-and-executable sections found.");

        var details = offenders
            .Select(s => $"{s.Name}: characteristics=0x{s.Characteristics:X8} (W={s.IsWritable}, X={s.IsExecutable}, S={s.IsShared})")
            .ToList();
        return CheckResult.Fail(Name, $"Found {offenders.Count} writable+executable section(s).", details);
    }
}

/// <summary>
/// ExecutableImportsCheck – the Import Address Table should live in a non-executable section.
/// An executable IAT is a classic exploitation sink.
/// </summary>
public sealed class ExecutableImportsCheck : ICheck
{
    public string Name => "ExecutableImportsCheck";
    public string Description => "Verifies the Import Address Table does not reside in an executable section.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – native IAT layout is not security-critical.");

        var iatDir = pe.Headers.GetDirectory(PEConstants.DirectoryImportAddressTable);
        if (iatDir.IsEmpty)
        {
            // Fall back to walking regular imports.
            var imports = pe.ReadImports();
            if (imports.Count == 0)
                return CheckResult.NotApplicable(Name, "Image has no imports.");

            var bad = imports
                .Select(i => new { i.DllName, Section = pe.SectionContaining(i.FirstThunkRva) })
                .Where(x => x.Section is { IsExecutable: true })
                .ToList();

            if (bad.Count == 0)
                return CheckResult.Pass(Name, "All import thunks live in non-executable sections.");

            var details = bad.Select(x => $"{x.DllName} IAT located in executable section '{x.Section!.Name}'.").ToList();
            return CheckResult.Fail(Name, "One or more IAT entries live in an executable section.", details);
        }

        var sec = pe.SectionContaining(iatDir.RelativeVirtualAddress);
        if (sec is null)
            return CheckResult.Error(Name, $"IAT RVA 0x{iatDir.RelativeVirtualAddress:X} does not map to any section.");

        if (sec.IsExecutable)
            return CheckResult.Fail(Name,
                $"IAT is located in executable section '{sec.Name}' (characteristics=0x{sec.Characteristics:X8}).");

        return CheckResult.Pass(Name, $"IAT is located in non-executable section '{sec.Name}'.");
    }
}
