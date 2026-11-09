namespace BinSight.Core.PE;

/// <summary>Single <c>IMAGE_DEBUG_DIRECTORY</c> entry.</summary>
public sealed record DebugEntry(
    uint Characteristics,
    uint TimeDateStamp,
    ushort MajorVersion,
    ushort MinorVersion,
    uint Type,
    uint SizeOfData,
    uint AddressOfRawData,
    uint PointerToRawData)
{
    public string TypeName => Type switch
    {
        PEConstants.DebugTypeUnknown    => "UNKNOWN",
        PEConstants.DebugTypeCoff       => "COFF",
        PEConstants.DebugTypeCodeview   => "CODEVIEW",
        PEConstants.DebugTypeFpo        => "FPO",
        PEConstants.DebugTypeMisc       => "MISC",
        PEConstants.DebugTypeException  => "EXCEPTION",
        PEConstants.DebugTypeFixup      => "FIXUP",
        PEConstants.DebugTypeOmapToSrc  => "OMAP_TO_SRC",
        PEConstants.DebugTypeOmapFromSrc => "OMAP_FROM_SRC",
        PEConstants.DebugTypeBorland    => "BORLAND",
        PEConstants.DebugTypeClsid      => "CLSID",
        PEConstants.DebugTypeVcFeature  => "VC_FEATURE",
        PEConstants.DebugTypePogo       => "POGO",
        PEConstants.DebugTypeIltcg      => "ILTCG",
        PEConstants.DebugTypeMpx        => "MPX",
        PEConstants.DebugTypeRepro      => "REPRO",
        PEConstants.DebugTypeExDllCharacteristics => "EX_DLLCHARACTERISTICS",
        _ => $"TYPE_{Type}",
    };
}

/// <summary>Information extracted from a <c>DEBUG_TYPE_CODEVIEW</c> RSDS record.</summary>
public sealed record CodeViewInfo(Guid Signature, uint Age, string PdbPath);
