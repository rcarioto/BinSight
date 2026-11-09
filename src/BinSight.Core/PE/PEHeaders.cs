namespace BinSight.Core.PE;

/// <summary>
/// COFF/PE header information collected from a <see cref="PEFile"/>.
/// </summary>
public sealed record PEHeaders(
    ushort Machine,
    ushort NumberOfSections,
    uint TimeDateStamp,
    uint PointerToSymbolTable,
    uint NumberOfSymbols,
    ushort SizeOfOptionalHeader,
    ushort Characteristics,
    ushort OptionalMagic,
    byte MajorLinkerVersion,
    byte MinorLinkerVersion,
    uint SizeOfCode,
    uint AddressOfEntryPoint,
    uint BaseOfCode,
    ulong ImageBase,
    uint SectionAlignment,
    uint FileAlignment,
    ushort MajorOperatingSystemVersion,
    ushort MinorOperatingSystemVersion,
    ushort MajorImageVersion,
    ushort MinorImageVersion,
    ushort MajorSubsystemVersion,
    ushort MinorSubsystemVersion,
    uint SizeOfImage,
    uint SizeOfHeaders,
    uint CheckSum,
    ushort Subsystem,
    ushort DllCharacteristics,
    ulong SizeOfStackReserve,
    ulong SizeOfStackCommit,
    ulong SizeOfHeapReserve,
    ulong SizeOfHeapCommit,
    uint LoaderFlags,
    uint NumberOfRvaAndSizes,
    DataDirectory[] DataDirectories)
{
    public bool IsPe32Plus => OptionalMagic == PEConstants.OptionalHeaderMagicPe32Plus;
    public bool IsDll => (Characteristics & PEConstants.FileDll) != 0;
    public bool Is32Bit => !IsPe32Plus;
    public bool Is64Bit => IsPe32Plus;
    public bool RelocsStripped => (Characteristics & PEConstants.FileRelocsStripped) != 0;
    public bool HasRelocations =>
        !GetDirectory(PEConstants.DirectoryBaseRelocationTable).IsEmpty;

    public string MachineName => Machine switch
    {
        PEConstants.MachineI386  => "x86",
        PEConstants.MachineAmd64 => "x64",
        PEConstants.MachineArm   => "ARM",
        PEConstants.MachineArm64 => "ARM64",
        PEConstants.MachineIa64  => "IA64",
        _ => $"0x{Machine:X4}",
    };

    /// <summary>
    /// Returns the data directory at the specified index, or <see cref="DataDirectory.Empty"/>
    /// if the index is out of range.
    /// </summary>
    public DataDirectory GetDirectory(int index)
    {
        if (index < 0 || index >= DataDirectories.Length)
        {
            return DataDirectory.Empty;
        }
        return DataDirectories[index];
    }
}

/// <summary>
/// A PE optional-header data directory entry (RVA + size).
/// </summary>
public readonly record struct DataDirectory(uint RelativeVirtualAddress, uint Size)
{
    public static readonly DataDirectory Empty = new(0, 0);
    public bool IsEmpty => RelativeVirtualAddress == 0 && Size == 0;
}
