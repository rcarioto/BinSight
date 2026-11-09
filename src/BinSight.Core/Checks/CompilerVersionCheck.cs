using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>
/// CompilerVersionCheck – fails when the image was linked with an older toolset than the policy allows.
/// Reads the Rich header to recover compiler/linker build numbers, and falls back to the optional-header
/// MajorLinkerVersion when the Rich header is missing.
/// </summary>
public sealed class CompilerVersionCheck : ICheck
{
    public string Name => "CompilerVersionCheck";
    public string Description => "Verifies the image was built with a recent enough Microsoft C/C++ toolset.";
    public bool EnabledByDefault => true;

    // Defaults: Visual Studio 2017 shipped linker 14.10 and compiler 19.10. BinScope 2014 used a laxer bar;
    // BinSight picks a modern floor that can still be overridden on the command line.
    private const int DefaultMinLinkerMajor   = 14;
    private const int DefaultMinLinkerMinor   = 0;
    private const int DefaultMinCompilerMajor = 17; // comp.id build >= 17 covers VS2017+ MSVC objects
    private const int DefaultMinCompilerMinor = 0;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        int minLinkerMajor = ctx.MinimumLinkerVersionMajor > 0 ? ctx.MinimumLinkerVersionMajor : DefaultMinLinkerMajor;
        int minLinkerMinor = ctx.MinimumLinkerVersionMinor;

        int imgLinkerMajor = pe.Headers.MajorLinkerVersion;
        int imgLinkerMinor = pe.Headers.MinorLinkerVersion;
        var details = new List<string>
        {
            $"Linker version in optional header: {imgLinkerMajor}.{imgLinkerMinor:D2}",
        };

        var rich = pe.TryReadRichHeader();
        if (rich is not null)
        {
            details.Add($"Rich header entries: {rich.Entries.Count}");
            foreach (var e in rich.Entries)
            {
                details.Add($"  prodid=0x{e.ProductId:X4} ({e.ProductName}), build={e.BuildNumber}, count={e.UseCount}");
            }
        }
        else
        {
            details.Add("Rich header: <not present>");
        }

        if (imgLinkerMajor < minLinkerMajor ||
            (imgLinkerMajor == minLinkerMajor && imgLinkerMinor < minLinkerMinor))
        {
            return CheckResult.Fail(Name,
                $"Image was linked with {imgLinkerMajor}.{imgLinkerMinor:D2}; minimum policy is {minLinkerMajor}.{minLinkerMinor:D2}.",
                details);
        }

        return CheckResult.Pass(Name,
            $"Image was linked with {imgLinkerMajor}.{imgLinkerMinor:D2} (>= policy {minLinkerMajor}.{minLinkerMinor:D2}).",
            details);
    }
}
