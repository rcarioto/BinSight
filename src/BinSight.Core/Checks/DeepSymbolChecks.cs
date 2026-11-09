using BinSight.Core.PE;
using BinSight.Core.Symbols;

namespace BinSight.Core.Checks;

/// <summary>
/// Maps SafeSEH handler RVAs to symbol names when a PDB (via DbgHelp) or exports are available.
/// </summary>
public sealed class SafeSEHSymbolsCheck : ICheck
{
    public string Name => "SafeSEHSymbolsCheck";
    public string Description => "When symbols are available, names each SafeSEH handler RVA (classic BinScope private-symbol depth).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.Headers.Is64Bit || pe.Headers.Machine != PEConstants.MachineI386)
            return CheckResult.NotApplicable(Name, "SafeSEH handler naming applies to 32-bit x86 images only.");

        var lc = pe.TryReadLoadConfig();
        if (lc is null || !lc.HasSafeSehTable)
            return CheckResult.NotApplicable(Name, "No SafeSEH handler table to name; see SafeSEHCheck.");

        var deep = ctx.DeepSymbols ?? DeepSymbolAnalysis.Analyze(
            pe, ctx.SymbolStatus ?? SymbolStatus.None(), ctx.SymbolSearchPath);

        var details = new List<string>(deep.Notes);
        details.Add($"Handlers ({deep.SafeSehHandlers.Count}):");
        details.AddRange(deep.SafeSehHandlers.Take(40).Select(h => "  " + h));
        if (deep.SafeSehHandlers.Count > 40)
            details.Add($"  … and {deep.SafeSehHandlers.Count - 40} more");

        int named = deep.SafeSehHandlers.Count(h => !h.StartsWith("RVA_", StringComparison.Ordinal));
        if (named == 0)
        {
            return CheckResult.Pass(Name,
                $"SafeSEH table has {deep.SafeSehHandlers.Count} handler(s) but none could be named. " +
                "Provide a matching PDB on Windows (/SymPath) for DbgHelp attribution.",
                details);
        }

        return CheckResult.Pass(Name,
            $"Named {named}/{deep.SafeSehHandlers.Count} SafeSEH handler(s)" +
            (deep.UsedDbgHelp ? " via DbgHelp." : " via export/PDB map."),
            details);
    }
}

/// <summary>
/// Per-function /GS coverage via relative-call scan to __security_check_cookie, attributed with symbols.
/// </summary>
public sealed class GSFunctionCoverageCheck : ICheck
{
    public string Name => "GSFunctionCoverageCheck";
    public string Description => "When symbols resolve __security_check_cookie, lists functions that call it (heuristic coverage).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.IsManaged)
            return CheckResult.NotApplicable(Name, "Managed (.NET) image – native /GS call-site coverage does not apply.");

        var status = ctx.SymbolStatus ?? SymbolResolver.Resolve(pe, ctx.SymbolSearchPath);
        var deep = ctx.DeepSymbols ?? DeepSymbolAnalysis.Analyze(pe, status, ctx.SymbolSearchPath);

        var details = new List<string>(deep.Notes);
        if (deep.GsCheckSymbol is null)
        {
            return CheckResult.Pass(Name,
                "Could not resolve __security_check_cookie. Header-level GSCheck still applies. " +
                "A matching PDB on Windows enables per-function /GS attribution.",
                details);
        }

        details.Add($"GS check symbol: {deep.GsCheckSymbol}");
        if (deep.GsInstrumentedFunctions.Count == 0)
        {
            return CheckResult.Pass(Name,
                $"Resolved {deep.GsCheckSymbol} but found no relative call sites in executable sections " +
                "(may use indirect calls, CFG dispatch, or non-E8 sequences).",
                details);
        }

        details.Add($"Instrumented / calling functions ({deep.GsInstrumentedFunctions.Count}):");
        details.AddRange(deep.GsInstrumentedFunctions.Take(50).Select(f => "  " + f));
        if (deep.GsInstrumentedFunctions.Count > 50)
            details.Add($"  … and {deep.GsInstrumentedFunctions.Count - 50} more");

        return CheckResult.Pass(Name,
            $"Attributed {deep.GsInstrumentedFunctions.Count} function(s) with calls to {deep.GsCheckSymbol}.",
            details);
    }
}
