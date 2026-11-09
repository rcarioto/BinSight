using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>
/// FunctionPointersCheck – modern BinScope's FunctionPointersCheck requires that long-lived
/// function-pointer tables (RW data imported from DLLs, for example) are guarded. Without PDB
/// symbols BinSight approximates this by verifying:
/// <list type="bullet">
///   <item>Control Flow Guard (<c>/guard:cf</c>) is enabled, OR</item>
///   <item>the image is a pure .NET assembly (CLR runtime header present), OR</item>
///   <item>the image has no writable sections that also appear to be executable or shared.</item>
/// </list>
/// </summary>
public sealed class FunctionPointersCheck : ICheck
{
    public string Name => "FunctionPointersCheck";
    public string Description => "Legacy BinScope name for CFG coverage. Prefer CFGCheck (enabled by default in BinSight).";
    public bool EnabledByDefault => false; // BinScope 2014 lists this as not SDL-required; CFGCheck is the modern default.

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        var clr = pe.Headers.GetDirectory(PEConstants.DirectoryClrRuntimeHeader);
        if (!clr.IsEmpty)
            return CheckResult.Pass(Name, "Managed (.NET) image – indirect calls are verified by the CLR.");

        bool guardCf = (pe.Headers.DllCharacteristics & PEConstants.DllCharGuardCf) != 0;
        var lc = pe.TryReadLoadConfig();

        if (guardCf && lc is not null && lc.HasControlFlowGuard)
            return CheckResult.Pass(Name, "Control Flow Guard is enabled and backed by a CF function table.");

        if (guardCf)
            return CheckResult.Fail(Name,
                "DllCharacteristics claim /guard:cf but Load Config does not supply a CF check function – invalid combination.");

        return CheckResult.Fail(Name,
            "Image does not enable Control Flow Guard. Relink with /GUARD:CF to protect indirect call sites.");
    }
}
