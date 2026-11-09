using System.Buffers.Binary;
using System.Text;

namespace BinSight.Core.Formats;

/// <summary>Minimal ELF parser for security-mitigation checks (PIE, NX, RELRO, canary, Fortify).</summary>
public sealed class ElfFile
{
    public string FilePath { get; }
    public bool Is64Bit { get; }
    public bool IsLittleEndian { get; }
    public ushort Type { get; } // ET_EXEC=2, ET_DYN=3
    public ushort Machine { get; }
    public IReadOnlyList<ElfPhdr> ProgramHeaders { get; }
    public IReadOnlyList<string> DynamicNeeded { get; }
    public IReadOnlyList<string> DynamicSymbols { get; }
    public bool HasBindNow { get; }
    public bool HasGnuRelro { get; }
    public bool HasExecutableStack { get; }
    public bool IsPie => Type == 3; // ET_DYN (PIE executables are ET_DYN)

    private readonly byte[] _image;

    private ElfFile(
        string path, byte[] image, bool is64, bool le, ushort type, ushort machine,
        IReadOnlyList<ElfPhdr> phdrs, IReadOnlyList<string> needed, IReadOnlyList<string> dynsyms,
        bool bindNow, bool gnuRelro, bool execStack)
    {
        FilePath = path;
        _image = image;
        Is64Bit = is64;
        IsLittleEndian = le;
        Type = type;
        Machine = machine;
        ProgramHeaders = phdrs;
        DynamicNeeded = needed;
        DynamicSymbols = dynsyms;
        HasBindNow = bindNow;
        HasGnuRelro = gnuRelro;
        HasExecutableStack = execStack;
    }

    public static ElfFile Load(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        if (bytes.Length < 52 || bytes[0] != 0x7F || bytes[1] != (byte)'E' || bytes[2] != (byte)'L' || bytes[3] != (byte)'F')
            throw new InvalidDataException("Not an ELF file.");

        bool is64 = bytes[4] == 2;
        bool le = bytes[5] == 1;
        ushort type = Read16(bytes, 16, le);
        ushort machine = Read16(bytes, 18, le);

        ulong phoff = is64 ? Read64(bytes, 32, le) : Read32(bytes, 28, le);
        ushort phentsize = Read16(bytes, is64 ? 54 : 42, le);
        ushort phnum = Read16(bytes, is64 ? 56 : 44, le);

        var phdrs = new List<ElfPhdr>(phnum);
        bool gnuRelro = false;
        bool execStack = false;
        ulong dynOff = 0, dynSz = 0;

        for (int i = 0; i < phnum; i++)
        {
            int off = (int)phoff + i * phentsize;
            if (off + phentsize > bytes.Length) break;
            uint pType = Read32(bytes, off, le);
            uint flags = is64 ? Read32(bytes, off + 4, le) : Read32(bytes, off + 24, le);
            ulong pOffset = is64 ? Read64(bytes, off + 8, le) : Read32(bytes, off + 4, le);
            ulong pFilesz = is64 ? Read64(bytes, off + 32, le) : Read32(bytes, off + 16, le);
            phdrs.Add(new ElfPhdr(pType, flags, pOffset, pFilesz));

            if (pType == 2) { dynOff = pOffset; dynSz = pFilesz; } // PT_DYNAMIC
            if (pType == 0x6474e552) gnuRelro = true; // PT_GNU_RELRO
            if (pType == 0x6474e551) // PT_GNU_STACK
                execStack = (flags & 1) != 0; // PF_X
        }

        var needed = new List<string>();
        var dynsyms = new List<string>();
        bool bindNow = false;

        if (dynSz > 0 && dynOff + dynSz <= (ulong)bytes.Length)
        {
            ParseDynamic(bytes, (int)dynOff, (int)dynSz, is64, le, needed, dynsyms, ref bindNow);
        }

        // Also scan whole image for well-known canary / fortify symbol strings as fallback.
        ScanAsciiHints(bytes, dynsyms);

        return new ElfFile(path, bytes, is64, le, type, machine, phdrs, needed, dynsyms, bindNow, gnuRelro, execStack);
    }

    public bool HasStackCanary =>
        DynamicSymbols.Any(s => s.Contains("stack_chk", StringComparison.OrdinalIgnoreCase));

    public bool HasFortify =>
        DynamicSymbols.Any(s => s.Contains("__sprintf_chk", StringComparison.Ordinal) ||
                                s.Contains("__memcpy_chk", StringComparison.Ordinal) ||
                                s.Contains("_chk", StringComparison.Ordinal));

    private static void ParseDynamic(
        byte[] bytes, int off, int size, bool is64, bool le,
        List<string> needed, List<string> dynsyms, ref bool bindNow)
    {
        int stride = is64 ? 16 : 8;
        ulong strtab = 0;
        var neededOffsets = new List<ulong>();
        for (int i = 0; i + stride <= size; i += stride)
        {
            long tag = is64 ? (long)Read64(bytes, off + i, le) : (int)Read32(bytes, off + i, le);
            ulong val = is64 ? Read64(bytes, off + i + 8, le) : Read32(bytes, off + i + 4, le);
            if (tag == 0) break; // DT_NULL
            if (tag == 1) neededOffsets.Add(val); // DT_NEEDED
            if (tag == 5) strtab = val; // DT_STRTAB — often VMA; may not match file offset without segments
            if (tag is 24 or 0x6ffffffb) bindNow = true; // DT_BIND_NOW / DT_FLAGS_1 bits approximated
            if (tag == 0x6ffffffb && (val & 8) != 0) bindNow = true; // DF_1_NOW
        }

        // Best-effort: if strtab looks like a file offset, resolve DT_NEEDED.
        if (strtab > 0 && strtab < (ulong)bytes.Length)
        {
            foreach (var nOff in neededOffsets)
            {
                ulong pos = strtab + nOff;
                if (pos < (ulong)bytes.Length)
                {
                    string s = ReadAsciiZ(bytes, (int)pos, 256);
                    if (!string.IsNullOrEmpty(s)) needed.Add(s);
                }
            }
        }
    }

    private static void ScanAsciiHints(byte[] bytes, List<string> dynsyms)
    {
        foreach (var needle in new[] { "__stack_chk_fail", "__stack_chk_guard", "__memcpy_chk", "__sprintf_chk", "__fortify_fail" })
        {
            byte[] n = Encoding.ASCII.GetBytes(needle);
            if (IndexOf(bytes, n) >= 0 && !dynsyms.Contains(needle))
                dynsyms.Add(needle);
        }
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        for (int i = 0; i <= hay.Length - needle.Length; i++)
        {
            int j = 0;
            for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
            if (j == needle.Length) return i;
        }
        return -1;
    }

    private static string ReadAsciiZ(byte[] b, int off, int max)
    {
        int end = Math.Min(b.Length, off + max);
        int i = off;
        while (i < end && b[i] != 0) i++;
        return Encoding.ASCII.GetString(b, off, i - off);
    }

    private static ushort Read16(byte[] b, int o, bool le) =>
        le ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o, 2))
           : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(o, 2));

    private static uint Read32(byte[] b, int o, bool le) =>
        le ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o, 4))
           : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o, 4));

    private static ulong Read64(byte[] b, int o, bool le) =>
        le ? BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o, 8))
           : BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(o, 8));
}

public readonly record struct ElfPhdr(uint Type, uint Flags, ulong Offset, ulong FileSize);
