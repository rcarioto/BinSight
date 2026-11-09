namespace BinSight.Core.PE;

/// <summary>
/// Portions of <c>IMAGE_LOAD_CONFIG_DIRECTORY</c> we care about for security checks.
/// Not every field is always present – this record exposes what was readable.
/// </summary>
public sealed record LoadConfig(
    uint Size,
    uint TimeDateStamp,
    ushort MajorVersion,
    ushort MinorVersion,
    uint GlobalFlagsClear,
    uint GlobalFlagsSet,
    uint CriticalSectionDefaultTimeout,
    ulong DeCommitFreeBlockThreshold,
    ulong DeCommitTotalFreeThreshold,
    ulong LockPrefixTable,
    ulong MaximumAllocationSize,
    ulong VirtualMemoryThreshold,
    ulong ProcessAffinityMask,
    uint ProcessHeapFlags,
    ushort CsdVersion,
    ushort DependentLoadFlags,
    ulong EditList,
    ulong SecurityCookie,
    ulong SEHandlerTable,
    ulong SEHandlerCount,
    ulong GuardCfCheckFunctionPointer,
    ulong GuardCfDispatchFunctionPointer,
    ulong GuardCfFunctionTable,
    ulong GuardCfFunctionCount,
    uint GuardFlags)
{
    /// <summary>True when the load-config indicates SafeSEH data is present (32-bit only).</summary>
    public bool HasSafeSehTable => SEHandlerTable != 0 && SEHandlerCount != 0;

    /// <summary>True when a non-null security cookie pointer is present.</summary>
    public bool HasSecurityCookie => SecurityCookie != 0;

    /// <summary>True when Control Flow Guard appears configured.</summary>
    public bool HasControlFlowGuard =>
        (GuardFlags & PEConstants.GuardCfInstrumented) != 0 &&
        GuardCfCheckFunctionPointer != 0;
}
