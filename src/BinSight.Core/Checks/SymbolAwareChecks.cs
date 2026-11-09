using BinSight.Core.PE;
using BinSight.Core.Symbols;

namespace BinSight.Core.Checks;

/// <summary>
/// SymbolsCheck – always runs. Reports whether symbols were found and what that unlocks.
/// Unlike BinScope 2014, missing symbols never block the rest of the analysis.
/// </summary>
public sealed class SymbolsCheck : ICheck
{
    public string Name => "SymbolsCheck";
    public string Description => "Reports PDB availability and what analysis is possible with/without symbols.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        var status = ctx.SymbolStatus ?? SymbolResolver.Resolve(pe, ctx.SymbolSearchPath);
        var details = new List<string>(status.AdvisoryNotes);
        if (status.FoundPublicHints.Count > 0)
            details.Add("Public hints: " + string.Join(", ", status.FoundPublicHints));
        if (status.CodeViewGuid is Guid g)
            details.Add($"CodeView GUID={g}, age={status.CodeViewAge}");

        return status.Availability switch
        {
            SymbolAvailability.Located =>
                CheckResult.Pass(Name, status.Summary, details),
            SymbolAvailability.LocatedButUnreadable =>
                CheckResult.Pass(Name, status.Summary, details),
            SymbolAvailability.ReferencedButMissing =>
                CheckResult.Pass(Name, status.Summary + " Having the matching PDB would enable a more thorough analysis.", details),
            _ =>
                CheckResult.Pass(Name, status.Summary + " Having private symbols would enable a more thorough analysis.", details),
        };
    }
}

/// <summary>
/// GSSymbolsCheck – when a PDB is available, confirm CRT GS helpers are present.
/// Without symbols this check explains the gap rather than failing the build.
/// </summary>
public sealed class GSSymbolsCheck : ICheck
{
    public string Name => "GSSymbolsCheck";
    public string Description => "When symbols are available, confirms CRT /GS helpers; otherwise reports the no-symbol gap.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – native CRT GS helpers do not apply.");

        var status = ctx.SymbolStatus ?? SymbolResolver.Resolve(pe, ctx.SymbolSearchPath);

        if (!status.SymbolsAvailable)
        {
            return CheckResult.Pass(Name,
                "No usable PDB beside the image / on /SymPath. Header-level GSCheck/DefaultGSCookieCheck still apply. " +
                "Providing private symbols would enable per-function /GS coverage attribution (a BinScope 2014 private-symbol feature).",
                status.AdvisoryNotes.ToList());
        }

        bool hasInit = status.FoundPublicHints.Any(h =>
            h.Contains("security_init_cookie", StringComparison.OrdinalIgnoreCase));
        bool hasCheck = status.FoundPublicHints.Any(h =>
            h.Contains("security_check_cookie", StringComparison.OrdinalIgnoreCase));
        bool hasReport = status.FoundPublicHints.Any(h =>
            h.Contains("report_gsfailure", StringComparison.OrdinalIgnoreCase));

        var details = status.FoundPublicHints.ToList();

        if (hasInit || hasCheck || hasReport)
            return CheckResult.Pass(Name,
                "PDB probe located CRT /GS helper symbol(s).", details);

        return CheckResult.Fail(Name,
            "PDB was found but no CRT /GS helper symbol names were visible in a lightweight probe. " +
            "The image may lack /GS, or symbols may be private-only/stripped of public names.",
            details);
    }
}
