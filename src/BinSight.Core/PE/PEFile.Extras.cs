using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace BinSight.Core.PE;

public sealed partial class PEFile
{
    /// <summary>
    /// Reads <c>IMAGE_DLLCHARACTERISTICS_EX_*</c> from the
    /// <c>IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS</c> debug directory, if present.
    /// </summary>
    public uint TryReadExtendedDllCharacteristics()
    {
        foreach (var d in ReadDebugEntries())
        {
            if (d.Type != PEConstants.DebugTypeExDllCharacteristics) continue;
            if (d.SizeOfData < 4) continue;

            // Prefer PointerToRawData; fall back to RVA mapping.
            if (d.PointerToRawData != 0 && d.PointerToRawData + 4 <= (uint)_image.Length)
                return BinaryPrimitives.ReadUInt32LittleEndian(_image.AsSpan((int)d.PointerToRawData, 4));

            if (TryReadAtRva(d.AddressOfRawData, 4, out var bytes))
                return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        }
        return 0;
    }

    /// <summary>
    /// True when the Certificate Table (Authenticode) directory is non-empty.
    /// Note: the Certificate Table uses a <b>file offset</b>, not an RVA.
    /// </summary>
    public bool HasAuthenticodeCertificateTable
    {
        get
        {
            var dir = Headers.GetDirectory(PEConstants.DirectoryCertificateTable);
            if (dir.IsEmpty) return false;
            // VirtualAddress is a file offset for the security directory.
            return dir.RelativeVirtualAddress + dir.Size <= (uint)_image.Length;
        }
    }

    /// <summary>Returns basic info about the first WIN_CERTIFICATE blob, if any.</summary>
    public AuthenticodeInfo? TryReadAuthenticodeInfo()
    {
        var dir = Headers.GetDirectory(PEConstants.DirectoryCertificateTable);
        if (dir.IsEmpty) return null;
        uint fo = dir.RelativeVirtualAddress; // file offset
        if (fo + 8 > _image.Length) return null;

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(_image.AsSpan((int)fo, 4));
        ushort revision = BinaryPrimitives.ReadUInt16LittleEndian(_image.AsSpan((int)fo + 4, 2));
        ushort certType = BinaryPrimitives.ReadUInt16LittleEndian(_image.AsSpan((int)fo + 6, 2));
        if (length < 8 || fo + length > _image.Length) return null;

        return new AuthenticodeInfo(length, revision, certType, (int)(length - 8));
    }

    /// <summary>
    /// Extracts the embedded application manifest (RT_MANIFEST) as text, if present.
    /// Works without symbols; used for UAC / execution-level reporting.
    /// </summary>
    public string? TryReadEmbeddedManifest()
    {
        var dir = Headers.GetDirectory(PEConstants.DirectoryResourceTable);
        if (dir.IsEmpty || !TryRvaToFileOffset(dir.RelativeVirtualAddress, out uint rootFo))
            return null;

        // Walk: root -> type 24 (RT_MANIFEST) -> name/id -> language -> data entry.
        if (!TryFindResourceDataRva(rootFo, dir.RelativeVirtualAddress, typeId: 24, out uint dataRva, out uint dataSize))
            return null;
        if (!TryRvaToFileOffset(dataRva, out uint dataFo)) return null;
        if (dataFo + dataSize > _image.Length) return null;

        // Manifests are typically UTF-8 or UTF-16 LE XML.
        var raw = _image.AsSpan((int)dataFo, (int)dataSize);
        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
            return Encoding.Unicode.GetString(raw[2..]);
        if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(raw[2..]);
        // UTF-16 LE without BOM: lots of zeros in odd positions.
        if (raw.Length >= 4 && raw[1] == 0 && raw[3] == 0)
            return Encoding.Unicode.GetString(raw);

        string text = Encoding.UTF8.GetString(raw).Trim('\0');
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    /// <summary>Parses requestedExecutionLevel from an embedded manifest, if any.</summary>
    public ManifestSecurityInfo? TryReadManifestSecurity()
    {
        string? xml = TryReadEmbeddedManifest();
        if (xml is null) return null;

        try
        {
            // Strip BOM / leading junk before '<'
            int lt = xml.IndexOf('<');
            if (lt > 0) xml = xml[lt..];

            var doc = XDocument.Parse(xml, LoadOptions.None);

            var levelEl = doc.Descendants().FirstOrDefault(e =>
                e.Name.LocalName.Equals("requestedExecutionLevel", StringComparison.OrdinalIgnoreCase));

            string? level = levelEl?.Attribute("level")?.Value
                            ?? levelEl?.Attribute("Level")?.Value;
            string? uiAccess = levelEl?.Attribute("uiAccess")?.Value;

            bool dpiAware = doc.Descendants().Any(e =>
                e.Name.LocalName.Equals("dpiAware", StringComparison.OrdinalIgnoreCase) ||
                e.Name.LocalName.Equals("dpiAwareness", StringComparison.OrdinalIgnoreCase));

            // Also catch the older trustInfo string form via regex if XML parse missed attributes.
            if (level is null)
            {
                var m = Regex.Match(xml, @"requestedExecutionLevel[^>]*level\s*=\s*""([^""]+)""",
                    RegexOptions.IgnoreCase);
                if (m.Success) level = m.Groups[1].Value;
            }

            return new ManifestSecurityInfo(level, uiAccess, dpiAware, xml.Length);
        }
        catch
        {
            // Manifest present but not well-formed XML – still useful to report presence.
            var m = Regex.Match(xml, @"requestedExecutionLevel[^>]*level\s*=\s*""([^""]+)""",
                RegexOptions.IgnoreCase);
            return new ManifestSecurityInfo(
                m.Success ? m.Groups[1].Value : null,
                null,
                false,
                xml.Length);
        }
    }

    private bool TryFindResourceDataRva(uint rootFo, uint rootRva, uint typeId, out uint dataRva, out uint dataSize)
    {
        dataRva = 0; dataSize = 0;
        if (!TryGetResourceDirectoryEntries(rootFo, out _, out var typeEntries)) return false;

        ResourceDirEntry? typeMatch = null;
        foreach (var e in typeEntries)
        {
            if (!e.IsName && e.Id == typeId) { typeMatch = e; break; }
        }
        if (typeMatch is null) return false;

        uint typeDirFo = rootFo + (typeMatch.Value.OffsetToData & 0x7FFFFFFF);
        if (!TryGetResourceDirectoryEntries(typeDirFo, out _, out var nameEntries) || nameEntries.Count == 0)
            return false;

        // Take the first name/id entry.
        uint nameDirFo = rootFo + (nameEntries[0].OffsetToData & 0x7FFFFFFF);
        if (!TryGetResourceDirectoryEntries(nameDirFo, out _, out var langEntries) || langEntries.Count == 0)
            return false;

        uint dataEntryFo = rootFo + (langEntries[0].OffsetToData & 0x7FFFFFFF);
        if (dataEntryFo + 16 > _image.Length) return false;

        dataRva  = BinaryPrimitives.ReadUInt32LittleEndian(_image.AsSpan((int)dataEntryFo, 4));
        dataSize = BinaryPrimitives.ReadUInt32LittleEndian(_image.AsSpan((int)dataEntryFo + 4, 4));
        return dataSize > 0;
    }

    private bool TryGetResourceDirectoryEntries(uint dirFo, out ushort namedCount, out List<ResourceDirEntry> entries)
    {
        namedCount = 0;
        entries = new List<ResourceDirEntry>();
        if (dirFo + 16 > _image.Length) return false;

        namedCount = BinaryPrimitives.ReadUInt16LittleEndian(_image.AsSpan((int)dirFo + 12, 2));
        ushort idCount = BinaryPrimitives.ReadUInt16LittleEndian(_image.AsSpan((int)dirFo + 14, 2));
        int total = namedCount + idCount;
        uint entryFo = dirFo + 16;
        for (int i = 0; i < total; i++)
        {
            uint o = entryFo + (uint)(i * 8);
            if (o + 8 > _image.Length) break;
            uint name = BinaryPrimitives.ReadUInt32LittleEndian(_image.AsSpan((int)o, 4));
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(_image.AsSpan((int)o + 4, 4));
            bool isName = (name & 0x80000000) != 0;
            uint id = name & 0x7FFFFFFF;
            entries.Add(new ResourceDirEntry(isName, id, offset));
        }
        return entries.Count > 0;
    }

    private readonly record struct ResourceDirEntry(bool IsName, uint Id, uint OffsetToData);
}

/// <summary>Summary of an Authenticode certificate table entry.</summary>
public sealed record AuthenticodeInfo(uint Length, ushort Revision, ushort CertificateType, int BlobSize);

/// <summary>Security-relevant fields extracted from an embedded SxS manifest.</summary>
public sealed record ManifestSecurityInfo(
    string? RequestedExecutionLevel,
    string? UiAccess,
    bool DpiAwareDeclared,
    int ManifestByteLength);
