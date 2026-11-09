using BinSight.Core.PE;

namespace BinSight.Core.Checks;

/// <summary>DBCheck – verifies the image opts in to ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE).</summary>
public sealed class DBCheck : ICheck
{
    public string Name => "DBCheck";
    public string Description => "Verifies that the binary opts in to ASLR via IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (/DYNAMICBASE).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        bool dyn = (pe.Headers.DllCharacteristics & PEConstants.DllCharDynamicBase) != 0;
        return dyn
            ? CheckResult.Pass(Name, "Image is marked /DYNAMICBASE (ASLR enabled).")
            : CheckResult.Fail(Name, "Image is NOT marked /DYNAMICBASE. Relink with /DYNAMICBASE to enable ASLR.");
    }
}

/// <summary>NXCheck – verifies the image opts in to DEP (IMAGE_DLLCHARACTERISTICS_NX_COMPAT).</summary>
public sealed class NXCheck : ICheck
{
    public string Name => "NXCheck";
    public string Description => "Verifies that the binary opts in to DEP via IMAGE_DLLCHARACTERISTICS_NX_COMPAT (/NXCOMPAT).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        bool nx = (pe.Headers.DllCharacteristics & PEConstants.DllCharNxCompat) != 0;
        return nx
            ? CheckResult.Pass(Name, "Image is marked /NXCOMPAT (DEP enabled).")
            : CheckResult.Fail(Name, "Image is NOT marked /NXCOMPAT. Relink with /NXCOMPAT to enable DEP.");
    }
}

/// <summary>
/// HighEntropyVACheck – verifies 64-bit images opt in to 64-bit address space layout randomization
/// (IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA).
/// </summary>
public sealed class HighEntropyVACheck : ICheck
{
    public string Name => "HighEntropyVACheck";
    public string Description => "Verifies 64-bit images opt in to High-Entropy ASLR (/HIGHENTROPYVA).";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (!pe.Headers.Is64Bit)
            return CheckResult.NotApplicable(Name, "Only applicable to PE32+ (64-bit) images.");

        // High-entropy ASLR requires DYNAMIC_BASE as well.
        bool dyn = (pe.Headers.DllCharacteristics & PEConstants.DllCharDynamicBase) != 0;
        bool he  = (pe.Headers.DllCharacteristics & PEConstants.DllCharHighEntropyVa) != 0;

        if (he && dyn)
            return CheckResult.Pass(Name, "Image is marked /HIGHENTROPYVA with /DYNAMICBASE.");

        if (!dyn)
            return CheckResult.Fail(Name, "High-entropy ASLR requires /DYNAMICBASE to also be set.");

        return CheckResult.Fail(Name, "Image is NOT marked /HIGHENTROPYVA. Relink with /HIGHENTROPYVA.");
    }
}

/// <summary>
/// AppContainerCheck – required for Windows Store certification, verifies
/// IMAGE_DLLCHARACTERISTICS_APPCONTAINER.
/// </summary>
public sealed class AppContainerCheck : ICheck
{
    public string Name => "AppContainerCheck";
    public string Description => "Verifies the image is marked /APPCONTAINER (required for Windows Store apps).";
    public bool EnabledByDefault => false; // Not SDL-required per BinScope 2014 guide.

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        bool ac = (pe.Headers.DllCharacteristics & PEConstants.DllCharAppContainer) != 0;
        return ac
            ? CheckResult.Pass(Name, "Image is marked /APPCONTAINER.")
            : CheckResult.Fail(Name, "Image is NOT marked /APPCONTAINER.");
    }
}
