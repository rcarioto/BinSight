namespace BinSight.Core.PE;

/// <summary>
/// A single PE section header entry (<c>IMAGE_SECTION_HEADER</c>).
/// </summary>
public sealed record SectionHeader(
    string Name,
    uint VirtualSize,
    uint VirtualAddress,
    uint SizeOfRawData,
    uint PointerToRawData,
    uint PointerToRelocations,
    uint PointerToLinenumbers,
    ushort NumberOfRelocations,
    ushort NumberOfLinenumbers,
    uint Characteristics)
{
    public bool IsExecutable => (Characteristics & PEConstants.SectionMemExecute) != 0;
    public bool IsWritable   => (Characteristics & PEConstants.SectionMemWrite) != 0;
    public bool IsReadable   => (Characteristics & PEConstants.SectionMemRead) != 0;
    public bool IsShared     => (Characteristics & PEConstants.SectionMemShared) != 0;
    public bool IsCode       => (Characteristics & PEConstants.SectionCntCode) != 0;

    /// <summary>True when this section contains the virtual address <paramref name="rva"/>.</summary>
    public bool ContainsRva(uint rva)
    {
        if (rva < VirtualAddress) return false;
        uint span = VirtualSize == 0 ? SizeOfRawData : VirtualSize;
        return rva < VirtualAddress + span;
    }
}
