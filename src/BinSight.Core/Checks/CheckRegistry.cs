namespace BinSight.Core.Checks;

/// <summary>Central catalogue of all built-in BinSight checks.</summary>
public static class CheckRegistry
{
    /// <summary>All built-in checks, in display order.</summary>
    public static IReadOnlyList<ICheck> All { get; } = new ICheck[]
    {
        // --- BinScope 2014 equivalents ---
        new AppContainerCheck(),
        new ATLVersionCheck(),
        new ATLVulnCheck(),
        new CompilerVersionCheck(),
        new DBCheck(),
        new DefaultGSCookieCheck(),
        new ExecutableImportsCheck(),
        new FunctionPointersCheck(),
        new GSCheck(),
        new GSFriendlyInitCheck(),
        new GSFunctionSafeBuffersCheck(),
        new HighEntropyVACheck(),
        new NXCheck(),
        new RSA32Check(),
        new SafeSEHCheck(),
        new SharedSectionCheck(),
        new VB6Check(),
        new WXCheck(),

        // --- Post-2014 / modern SDL ---
        new CFGCheck(),
        new CETCheck(),
        new RelocsStrippedCheck(),
        new AuthenticodeCheck(),
        new AuthenticodeVerifyCheck(),
        new DelayLoadCheck(),
        new ManifestUACCheck(),
        new ForceIntegrityCheck(),
        new ExtendedMitigationsCheck(),
        new DangerousApiCheck(),

        // --- Symbol-aware reporting (never blocks analysis when PDBs are missing) ---
        new SymbolsCheck(),
        new GSSymbolsCheck(),
        new SafeSEHSymbolsCheck(),
        new GSFunctionCoverageCheck(),

        // --- Custom / YARA-style policy hooks ---
        new CustomRulesCheck(),
        new YaraRulesCheck(),
    };

    /// <summary>Look up a check by case-insensitive name.</summary>
    public static ICheck? Find(string name) =>
        All.FirstOrDefault(c => string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>The default set (SDL 2014 + modern mitigations + symbol advisories).</summary>
    public static IEnumerable<ICheck> Defaults => All.Where(c => c.EnabledByDefault);

    /// <summary>Only the original BinScope 2014 check names (for /Profile binscope2014).</summary>
    public static IEnumerable<ICheck> BinScope2014 => All.Where(c => c switch
    {
        AppContainerCheck or ATLVersionCheck or ATLVulnCheck or CompilerVersionCheck or
            DBCheck or DefaultGSCookieCheck or ExecutableImportsCheck or FunctionPointersCheck or
            GSCheck or GSFriendlyInitCheck or GSFunctionSafeBuffersCheck or HighEntropyVACheck or
            NXCheck or RSA32Check or SafeSEHCheck or SharedSectionCheck or VB6Check or WXCheck
            => true,
        _ => false,
    });
}
