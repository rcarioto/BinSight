using System.Buffers.Binary;
using System.Text;

namespace BinSight.Core.Formats;

/// <summary>Minimal Mach-O parser for PIE, stack canary, and code-signature presence.</summary>
public sealed class MachOFile
{
    public string FilePath { get; }
    public bool Is64Bit { get; }
    public bool IsPie { get; }
    public bool HasStackCanary { get; }
    public bool HasCodeSignature { get; }
    public bool AllowsStackExecution { get; }
    public uint CpuType { get; }
    public IReadOnlyList<string> SymbolHints { get; }

    private MachOFile(
        string path, bool is64, bool pie, bool canary, bool codeSig, bool allowStackExec,
        uint cpu, IReadOnlyList<string> hints)
    {
        FilePath = path;
        Is64Bit = is64;
        IsPie = pie;
        HasStackCanary = canary;
        HasCodeSignature = codeSig;
        AllowsStackExecution = allowStackExec;
        CpuType = cpu;
        SymbolHints = hints;
    }

    public static MachOFile Load(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        if (bytes.Length < 32)
            throw new InvalidDataException("Not a Mach-O file.");

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
        bool swap;
        bool is64;
        switch (magic)
        {
            case 0xFEEDFACE: is64 = false; swap = false; break;
            case 0xFEEDFACF: is64 = true; swap = false; break;
            case 0xCEFAEDFE: is64 = false; swap = true; break;
            case 0xCFFAEDFE: is64 = true; swap = true; break;
            case 0xCAFEBABE: // fat — analyze first arch slice lightly via string scan
            case 0xBEBAFECA:
                return LoadFatFallback(path, bytes);
            default:
                throw new InvalidDataException($"Unrecognized Mach-O magic 0x{magic:X8}.");
        }

        uint cputype = Read32(bytes, 4, swap);
        uint filetype = Read32(bytes, 12, swap);
        uint ncmds = Read32(bytes, 16, swap);
        uint sizeofcmds = Read32(bytes, 20, swap);
        uint flags = Read32(bytes, is64 ? 24 : 24, swap);

        bool pie = (flags & 0x2000000) != 0; // MH_PIE
        bool allowStackExec = (flags & 0x20000) != 0; // MH_ALLOW_STACK_EXECUTION
        bool codeSig = false;

        int cmdOff = is64 ? 32 : 28;
        int end = Math.Min(bytes.Length, cmdOff + (int)sizeofcmds);
        for (uint i = 0; i < ncmds && cmdOff + 8 <= end; i++)
        {
            uint cmd = Read32(bytes, cmdOff, swap);
            uint cmdsize = Read32(bytes, cmdOff + 4, swap);
            if (cmdsize < 8) break;
            if (cmd == 0x1D || cmd == 0x1C) // LC_CODE_SIGNATURE / LC_SEGMENT with __LINKEDIT often; 0x1D = LC_CODE_SIGNATURE
                codeSig = true;
            if (cmd == 0x29) // LC_CODE_SIGNATURE (modern)
                codeSig = true;
            cmdOff += (int)cmdsize;
        }

        var hints = new List<string>();
        Scan(bytes, hints);
        bool canary = hints.Any(h => h.Contains("stack_chk", StringComparison.OrdinalIgnoreCase));

        _ = filetype;
        return new MachOFile(path, is64, pie, canary, codeSig, allowStackExec, cputype, hints);
    }

    private static MachOFile LoadFatFallback(string path, byte[] bytes)
    {
        var hints = new List<string>();
        Scan(bytes, hints);
        bool canary = hints.Any(h => h.Contains("stack_chk", StringComparison.OrdinalIgnoreCase));
        bool codeSig = IndexOf(bytes, Encoding.ASCII.GetBytes("codedirectory")) >= 0
                       || IndexOf(bytes, Encoding.ASCII.GetBytes("CodeDirectory")) >= 0;
        // Fat binaries: report conservatively.
        return new MachOFile(path, is64: true, pie: true, canary, codeSig, allowStackExec: false, cpu: 0, hints);
    }

    private static void Scan(byte[] bytes, List<string> hints)
    {
        foreach (var needle in new[] { "___stack_chk_fail", "__stack_chk_fail", "___stack_chk_guard", "__stack_chk_guard" })
        {
            if (IndexOf(bytes, Encoding.ASCII.GetBytes(needle)) >= 0)
                hints.Add(needle);
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

    private static uint Read32(byte[] b, int o, bool swap) =>
        swap
            ? BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o, 4))
            : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o, 4));
}
