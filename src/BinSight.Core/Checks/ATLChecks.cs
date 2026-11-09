using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>
/// ATLVersionCheck – when the image links against ATL, require that it was built against ATL
/// bundled with a reasonably modern toolset (as encoded in the Rich header).
/// </summary>
public sealed class ATLVersionCheck : ICheck
{
    public string Name => "ATLVersionCheck";
    public string Description => "Verifies ATL-using images were built with a modern ATL (shipped with VS2015+).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (!HasAtlImports(pe))
            return CheckResult.NotApplicable(Name, "Image does not import ATL (ATL*.DLL).");

        var rich = pe.TryReadRichHeader();
        if (rich is null)
            return CheckResult.Error(Name,
                "ATL imports present but Rich header is missing; cannot determine ATL toolset version.");

        // Any Microsoft C/C++ compiler entry (Utc*) with build >= 23026 approximates VS2015 Update 3 or newer.
        var utc = rich.Entries
            .Where(e => e.ProductName.StartsWith("Utc", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (utc.Count == 0)
            return CheckResult.Fail(Name, "No Microsoft C/C++ (Utc) compiler entries found in Rich header; ATL version indeterminate.");

        ushort maxBuild = utc.Max(e => e.BuildNumber);
        var details = utc.Select(e => $"{e.ProductName} build {e.BuildNumber}").ToList();

        if (maxBuild < 23026)
            return CheckResult.Fail(Name,
                $"Highest Microsoft compiler build in Rich header is {maxBuild}; ATL may be out of date.",
                details);

        return CheckResult.Pass(Name,
            $"ATL-using image was built with modern tools (highest compiler build {maxBuild}).",
            details);
    }

    internal static bool HasAtlImports(PEFile pe)
    {
        foreach (var imp in pe.ReadImports())
        {
            if (imp.DllName.StartsWith("ATL", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        foreach (var dll in pe.ReadDelayLoadDllNames())
        {
            if (dll.StartsWith("ATL", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}

/// <summary>
/// ATLVulnCheck – fails ATL-using binaries built with toolsets known to carry CVE-2009-0901/
/// CVE-2009-2493 vulnerable ATL headers (anything before the VS2008 SP1 ATL security update).
/// </summary>
public sealed class ATLVulnCheck : ICheck
{
    public string Name => "ATLVulnCheck";
    public string Description => "Fails binaries built with ATL headers known to be vulnerable (CVE-2009-0901 / CVE-2009-2493).";
    public bool EnabledByDefault => true;

    // Compiler build numbers at or below this value are the vulnerable ATL vintage.
    // VS2008 RTM (CL build 21022) and earlier ship the pre-security-update ATL headers.
    private const ushort LastKnownVulnerableBuild = 21022;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (!ATLVersionCheck.HasAtlImports(pe))
            return CheckResult.NotApplicable(Name, "Image does not import ATL.");

        var rich = pe.TryReadRichHeader();
        if (rich is null)
            return CheckResult.Error(Name, "Rich header missing; cannot evaluate ATL build vintage.");

        var utc = rich.Entries
            .Where(e => e.ProductName.StartsWith("Utc", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (utc.Count == 0)
            return CheckResult.Error(Name, "Rich header contains no compiler entries; ATL vintage unknown.");

        ushort maxBuild = utc.Max(e => e.BuildNumber);
        if (maxBuild <= LastKnownVulnerableBuild)
        {
            return CheckResult.Fail(Name,
                $"Image was built with compiler build {maxBuild}, which ships the vulnerable ATL headers (CVE-2009-0901/2493).");
        }

        return CheckResult.Pass(Name,
            $"Image was built with compiler build {maxBuild}, past the vulnerable ATL vintage ({LastKnownVulnerableBuild}).");
    }
}
