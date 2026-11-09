using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>RSA32Check – fails if the deprecated RSA32.LIB appears to be linked in.</summary>
public sealed class RSA32Check : ICheck
{
    public string Name => "RSA32Check";
    public string Description => "Fails if the image appears to use the deprecated RSA32 library.";
    public bool EnabledByDefault => true;

    private static readonly string[] BannedDllPrefixes =
    {
        "RSA32", "RSABASE",
    };

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        var hits = new List<string>();
        foreach (var imp in pe.ReadImports())
        {
            foreach (var banned in BannedDllPrefixes)
            {
                if (imp.DllName.StartsWith(banned, StringComparison.OrdinalIgnoreCase))
                {
                    hits.Add($"Imports from {imp.DllName}");
                }
            }
        }
        foreach (var dll in pe.ReadDelayLoadDllNames())
        {
            foreach (var banned in BannedDllPrefixes)
            {
                if (dll.StartsWith(banned, StringComparison.OrdinalIgnoreCase))
                    hits.Add($"Delay-loads {dll}");
            }
        }

        if (hits.Count == 0)
            return CheckResult.Pass(Name, "No references to deprecated RSA32/RSABASE libraries.");

        return CheckResult.Fail(Name, "Image references deprecated RSA32/RSABASE libraries.", hits);
    }
}

/// <summary>VB6Check – fails if the image was produced by Visual Basic 6 / MSVBVM runtime.</summary>
public sealed class VB6Check : ICheck
{
    public string Name => "VB6Check";
    public string Description => "Fails if the image appears to be a Visual Basic 6 binary (MSVBVM60 runtime).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        foreach (var imp in pe.ReadImports())
        {
            if (imp.DllName.StartsWith("MSVBVM", StringComparison.OrdinalIgnoreCase))
                return CheckResult.Fail(Name, $"Image imports the VB6 runtime: {imp.DllName}.");
        }

        var rich = pe.TryReadRichHeader();
        if (rich is not null)
        {
            foreach (var e in rich.Entries)
            {
                if (e.ProductName.StartsWith("VisualBasic", StringComparison.OrdinalIgnoreCase))
                    return CheckResult.Fail(Name,
                        $"Rich header indicates Visual Basic tooling ({e.ProductName}).");
            }
        }

        return CheckResult.Pass(Name, "No evidence that the image was built with Visual Basic 6.");
    }
}
