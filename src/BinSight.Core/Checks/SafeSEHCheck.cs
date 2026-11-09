using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>
/// SafeSEHCheck – x86 images must either opt out of SEH (IMAGE_DLLCHARACTERISTICS_NO_SEH)
/// or declare a SafeSEH handler table in the Load Config. Not applicable to 64-bit images.
/// </summary>
public sealed class SafeSEHCheck : ICheck
{
    public string Name => "SafeSEHCheck";
    public string Description => "Verifies 32-bit images are linked with /SAFESEH (or opt out of SEH entirely).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (pe.Headers.Is64Bit)
            return CheckResult.NotApplicable(Name, "SafeSEH is only applicable to 32-bit (PE32) images.");

        if (pe.Headers.Machine != PEConstants.MachineI386)
            return CheckResult.NotApplicable(Name,
                $"SafeSEH is only applicable to x86 images (image machine = {pe.Headers.MachineName}).");

        bool noSeh = (pe.Headers.DllCharacteristics & PEConstants.DllCharNoSeh) != 0;
        if (noSeh)
            return CheckResult.Pass(Name, "Image is marked /SAFESEH:NO-SEH (no exception handlers).");

        var lc = pe.TryReadLoadConfig();
        if (lc is null)
            return CheckResult.Fail(Name, "No Load Config present; image cannot enumerate safe exception handlers.");

        if (lc.HasSafeSehTable)
            return CheckResult.Pass(Name,
                $"Image declares a SafeSEH handler table with {lc.SEHandlerCount} entries.");

        return CheckResult.Fail(Name,
            "Image has neither /SAFESEH handler table nor IMAGE_DLLCHARACTERISTICS_NO_SEH set.");
    }
}
