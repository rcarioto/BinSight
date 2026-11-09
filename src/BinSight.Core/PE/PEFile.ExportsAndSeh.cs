using System.Buffers.Binary;
using System.Text;

namespace BinSight.Core.PE;

public sealed partial class PEFile
{
    /// <summary>Export name → RVA (best-effort; forwarded exports skipped).</summary>
    public IReadOnlyDictionary<string, uint> ReadExportNameRvas()
    {
        var dir = Headers.GetDirectory(PEConstants.DirectoryExportTable);
        if (dir.IsEmpty || dir.Size < 40)
            return new Dictionary<string, uint>(StringComparer.Ordinal);

        if (!TryReadAtRva(dir.RelativeVirtualAddress, 40, out var hdr))
            return new Dictionary<string, uint>(StringComparer.Ordinal);

        uint numNames = BinaryPrimitives.ReadUInt32LittleEndian(hdr[24..28]);
        uint addrOfFunctions = BinaryPrimitives.ReadUInt32LittleEndian(hdr[28..32]);
        uint addrOfNames = BinaryPrimitives.ReadUInt32LittleEndian(hdr[32..36]);
        uint addrOfOrdinals = BinaryPrimitives.ReadUInt32LittleEndian(hdr[36..40]);
        if (numNames == 0 || numNames > 100_000)
            return new Dictionary<string, uint>(StringComparer.Ordinal);

        var map = new Dictionary<string, uint>(StringComparer.Ordinal);
        for (uint i = 0; i < numNames; i++)
        {
            if (!TryReadAtRva(addrOfNames + i * 4, 4, out var namePtrBytes)) break;
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(namePtrBytes);
            string? name = TryReadAsciiZ(nameRva, 512);
            if (name is null) continue;

            if (!TryReadAtRva(addrOfOrdinals + i * 2, 2, out var ordBytes)) break;
            ushort ord = BinaryPrimitives.ReadUInt16LittleEndian(ordBytes);

            if (!TryReadAtRva(addrOfFunctions + (uint)ord * 4, 4, out var fnBytes)) continue;
            uint fnRva = BinaryPrimitives.ReadUInt32LittleEndian(fnBytes);
            // Skip forwards (RVA falls inside export directory).
            if (fnRva >= dir.RelativeVirtualAddress && fnRva < dir.RelativeVirtualAddress + dir.Size)
                continue;
            if (fnRva != 0)
                map[name] = fnRva;
        }
        return map;
    }

    /// <summary>Reads SafeSEH handler RVAs from Load Config (PE32 only).</summary>
    public IReadOnlyList<uint> ReadSafeSehHandlerRvas()
    {
        var lc = TryReadLoadConfig();
        if (lc is null || !lc.HasSafeSehTable || Headers.Is64Bit)
            return Array.Empty<uint>();

        if (lc.SEHandlerCount > 100_000)
            return Array.Empty<uint>();

        uint tableRva = (uint)(lc.SEHandlerTable - Headers.ImageBase);
        int count = (int)lc.SEHandlerCount;
        int bytes = count * 4;
        if (!TryReadAtRva(tableRva, bytes, out var span))
            return Array.Empty<uint>();

        var list = new List<uint>(count);
        for (int i = 0; i < count; i++)
            list.Add(BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(i * 4, 4)));
        return list;
    }

    private string? TryReadAsciiZ(uint rva, int maxLen)
    {
        if (!TryRvaToFileOffset(rva, out uint fo)) return null;
        int end = Math.Min(_image.Length, (int)fo + maxLen);
        int len = 0;
        for (int i = (int)fo; i < end; i++, len++)
        {
            if (_image[i] == 0) break;
            if (_image[i] < 0x20 || _image[i] > 0x7E) return null;
        }
        if (len == 0) return null;
        return Encoding.ASCII.GetString(_image, (int)fo, len);
    }
}
