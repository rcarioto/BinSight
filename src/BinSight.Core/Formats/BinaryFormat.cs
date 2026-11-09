namespace BinSight.Core.Formats;

public enum BinaryFormat
{
    Unknown,
    Pe,
    Elf,
    MachO,
}

public static class BinaryFormatDetector
{
    public static BinaryFormat Detect(string path)
    {
        using var fs = File.OpenRead(path);
        Span<byte> hdr = stackalloc byte[4];
        int n = fs.Read(hdr);
        if (n < 2) return BinaryFormat.Unknown;

        // MZ / PE
        if (hdr[0] == (byte)'M' && hdr[1] == (byte)'Z')
            return BinaryFormat.Pe;

        // ELF \x7FELF
        if (n >= 4 && hdr[0] == 0x7F && hdr[1] == (byte)'E' && hdr[2] == (byte)'L' && hdr[3] == (byte)'F')
            return BinaryFormat.Elf;

        // Mach-O magics (32/64, endian variants)
        if (n >= 4)
        {
            uint magic = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(hdr);
            if (magic is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE or 0xCAFEBABE or 0xBEBAFECA)
                return BinaryFormat.MachO;
        }

        return BinaryFormat.Unknown;
    }
}
