using BinSight.Core.PE;
using BinSight.Core.Symbols;

namespace BinSight.Core.Checks;

/// <summary>Contract implemented by every BinSight check.</summary>
public interface ICheck
{
    /// <summary>Canonical name (matches the BinScope check name where applicable).</summary>
    string Name { get; }

    /// <summary>Short human-readable description for help / reports.</summary>
    string Description { get; }

    /// <summary>True if this check is enabled by the SDL-required default set.</summary>
    bool EnabledByDefault { get; }

    /// <summary>Execute this check against <paramref name="pe"/>.</summary>
    CheckResult Run(PEFile pe, CheckContext ctx);
}

/// <summary>Per-invocation configuration passed to each check.</summary>
public sealed class CheckContext
{
    public CheckContext(
        int minimumLinkerVersionMajor = 0,
        int minimumLinkerVersionMinor = 0,
        int minimumCompilerVersionMajor = 0,
        int minimumCompilerVersionMinor = 0,
        string? symbolSearchPath = null,
        SymbolStatus? symbolStatus = null,
        DeepSymbolAnalysis.Result? deepSymbols = null,
        string? customRulesPath = null,
        string? yaraRulesPath = null)
    {
        MinimumLinkerVersionMajor   = minimumLinkerVersionMajor;
        MinimumLinkerVersionMinor   = minimumLinkerVersionMinor;
        MinimumCompilerVersionMajor = minimumCompilerVersionMajor;
        MinimumCompilerVersionMinor = minimumCompilerVersionMinor;
        SymbolSearchPath            = symbolSearchPath;
        SymbolStatus                = symbolStatus;
        DeepSymbols                 = deepSymbols;
        CustomRulesPath             = customRulesPath;
        YaraRulesPath               = yaraRulesPath;
    }

    public int MinimumLinkerVersionMajor { get; }
    public int MinimumLinkerVersionMinor { get; }
    public int MinimumCompilerVersionMajor { get; }
    public int MinimumCompilerVersionMinor { get; }

    /// <summary>Optional PDB search path (<c>/SymPath</c>).</summary>
    public string? SymbolSearchPath { get; }

    /// <summary>Pre-resolved symbol status for this image (filled by <c>Analyzer</c>).</summary>
    public SymbolStatus? SymbolStatus { get; set; }

    /// <summary>Optional deep PDB/DbgHelp attribution (SafeSEH names, GS call sites).</summary>
    public DeepSymbolAnalysis.Result? DeepSymbols { get; set; }

    /// <summary>Optional JSON/YAML-like custom rules file (<c>/Rules</c>).</summary>
    public string? CustomRulesPath { get; }

    /// <summary>Optional YARA rules file or directory (<c>/Yara</c>).</summary>
    public string? YaraRulesPath { get; }

    public CheckContext WithSymbolStatus(SymbolStatus status) =>
        new(MinimumLinkerVersionMajor, MinimumLinkerVersionMinor,
            MinimumCompilerVersionMajor, MinimumCompilerVersionMinor,
            SymbolSearchPath, status, DeepSymbols, CustomRulesPath, YaraRulesPath);

    public CheckContext WithDeepSymbols(DeepSymbolAnalysis.Result deep) =>
        new(MinimumLinkerVersionMajor, MinimumLinkerVersionMinor,
            MinimumCompilerVersionMajor, MinimumCompilerVersionMinor,
            SymbolSearchPath, SymbolStatus, deep, CustomRulesPath, YaraRulesPath);
}
