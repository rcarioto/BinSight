using System.Buffers.Binary;
using System.Text;

namespace BinSight.Core.PE;

/// <summary>
/// A parsed, in-memory view over a Portable Executable file.
/// Supports both <b>PE32</b> (32-bit) and <b>PE32+</b> (64-bit) images.
/// </summary>
/// <remarks>
/// <para>This parser is deliberately self-contained; it does not depend on
/// <see cref="System.Reflection.PortableExecutable"/> because many of the fields BinSight
/// needs (full Load Config, Rich header, raw section flags, extended DLL characteristics,
/// debug directory payloads) are not surfaced by the BCL types.</para>
/// <para>Instances are immutable and safe to share across threads once constructed.</para>
/// </remarks>
public sealed partial class PEFile
{
    private readonly byte[] _image;

    public string FilePath { get; }
    public PEHeaders Headers { get; }
    public IReadOnlyList<SectionHeader> Sections { get; }
    public uint PeHeaderFileOffset { get; }

    /// <summary>
    /// True when the image carries a CLR runtime header (managed .NET assembly).
    /// Several native SDL checks do not apply to managed binaries.
    /// </summary>
    public bool IsManaged => !Headers.GetDirectory(PEConstants.DirectoryClrRuntimeHeader).IsEmpty;

    private PEFile(string path, byte[] image, PEHeaders headers, IReadOnlyList<SectionHeader> sections, uint peOffset)
    {
        FilePath = path;
        _image = image;
        Headers = headers;
        Sections = sections;
        PeHeaderFileOffset = peOffset;
    }

    /// <summary>Open and parse a PE file from disk.</summary>
    /// <exception cref="InvalidPEException">Thrown when the file is missing or malformed.</exception>
    public static PEFile Load(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("A target path is required.", nameof(path));
        if (!File.Exists(path))
            throw new InvalidPEException($"Target file not found: {path}");

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception ex)
        {
            throw new InvalidPEException($"Unable to read '{path}': {ex.Message}", ex);
        }

        return Parse(path, bytes);
    }

    /// <summary>Parse a PE from an in-memory byte array (used by tests).</summary>
    public static PEFile Parse(string path, byte[] bytes)
    {
        if (bytes.Length < 64)
            throw new InvalidPEException("File is too small to be a valid PE image.");

        ushort dosMagic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(0, 2));
        if (dosMagic != PEConstants.DosMagic)
            throw new InvalidPEException("File does not start with an MZ DOS header.");

        uint peOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0x3C, 4));
        if (peOffset == 0 || peOffset + 24 > bytes.Length)
            throw new InvalidPEException($"PE header offset 0x{peOffset:X} is out of range.");

        uint ntSig = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)peOffset, 4));
        if (ntSig != PEConstants.NtSignature)
            throw new InvalidPEException("Missing PE\\0\\0 signature; not a valid PE image.");

        // COFF file header: 20 bytes starting right after the PE signature.
        var coff = bytes.AsSpan((int)(peOffset + 4), 20);
        ushort machine     = BinaryPrimitives.ReadUInt16LittleEndian(coff[0..2]);
        ushort numSections = BinaryPrimitives.ReadUInt16LittleEndian(coff[2..4]);
        uint   timestamp   = BinaryPrimitives.ReadUInt32LittleEndian(coff[4..8]);
        uint   symTable    = BinaryPrimitives.ReadUInt32LittleEndian(coff[8..12]);
        uint   numSyms     = BinaryPrimitives.ReadUInt32LittleEndian(coff[12..16]);
        ushort optSize     = BinaryPrimitives.ReadUInt16LittleEndian(coff[16..18]);
        ushort chars       = BinaryPrimitives.ReadUInt16LittleEndian(coff[18..20]);

        int optOffset = (int)(peOffset + 24);
        if (optOffset + optSize > bytes.Length || optSize < 2)
            throw new InvalidPEException("Optional header is truncated.");

        ushort optMagic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(optOffset, 2));
        var headers = ParseOptionalHeader(bytes, optOffset, optMagic, machine, numSections,
            timestamp, symTable, numSyms, optSize, chars);

        var sections = ParseSections(bytes, optOffset + optSize, numSections);

        return new PEFile(path, bytes, headers, sections, peOffset);
    }

    private static PEHeaders ParseOptionalHeader(byte[] bytes, int offset, ushort magic,
        ushort machine, ushort numSections, uint timestamp, uint symTable, uint numSyms,
        ushort optSize, ushort chars)
    {
        bool plus = magic switch
        {
            PEConstants.OptionalHeaderMagicPe32 => false,
            PEConstants.OptionalHeaderMagicPe32Plus => true,
            _ => throw new InvalidPEException($"Unsupported optional-header magic 0x{magic:X4}."),
        };

        var span = bytes.AsSpan(offset);

        byte majorLinker = span[2];
        byte minorLinker = span[3];
        uint sizeOfCode  = BinaryPrimitives.ReadUInt32LittleEndian(span[4..8]);
        uint entry       = BinaryPrimitives.ReadUInt32LittleEndian(span[16..20]);
        uint baseOfCode  = BinaryPrimitives.ReadUInt32LittleEndian(span[20..24]);

        ulong imageBase;
        int cursor;
        if (plus)
        {
            imageBase = BinaryPrimitives.ReadUInt64LittleEndian(span[24..32]);
            cursor = 32;
        }
        else
        {
            imageBase = BinaryPrimitives.ReadUInt32LittleEndian(span[28..32]);
            cursor = 32;
        }

        uint sectionAlign = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
        uint fileAlign    = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
        ushort majorOs    = BinaryPrimitives.ReadUInt16LittleEndian(span[cursor..(cursor + 2)]); cursor += 2;
        ushort minorOs    = BinaryPrimitives.ReadUInt16LittleEndian(span[cursor..(cursor + 2)]); cursor += 2;
        ushort majorImage = BinaryPrimitives.ReadUInt16LittleEndian(span[cursor..(cursor + 2)]); cursor += 2;
        ushort minorImage = BinaryPrimitives.ReadUInt16LittleEndian(span[cursor..(cursor + 2)]); cursor += 2;
        ushort majorSub   = BinaryPrimitives.ReadUInt16LittleEndian(span[cursor..(cursor + 2)]); cursor += 2;
        ushort minorSub   = BinaryPrimitives.ReadUInt16LittleEndian(span[cursor..(cursor + 2)]); cursor += 2;
        cursor += 4; // Win32VersionValue (reserved, must be zero)
        uint sizeOfImage   = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
        uint sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
        uint checkSum      = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
        ushort subsystem   = BinaryPrimitives.ReadUInt16LittleEndian(span[cursor..(cursor + 2)]); cursor += 2;
        ushort dllChars    = BinaryPrimitives.ReadUInt16LittleEndian(span[cursor..(cursor + 2)]); cursor += 2;

        ulong stackReserve, stackCommit, heapReserve, heapCommit;
        if (plus)
        {
            stackReserve = BinaryPrimitives.ReadUInt64LittleEndian(span[cursor..(cursor + 8)]); cursor += 8;
            stackCommit  = BinaryPrimitives.ReadUInt64LittleEndian(span[cursor..(cursor + 8)]); cursor += 8;
            heapReserve  = BinaryPrimitives.ReadUInt64LittleEndian(span[cursor..(cursor + 8)]); cursor += 8;
            heapCommit   = BinaryPrimitives.ReadUInt64LittleEndian(span[cursor..(cursor + 8)]); cursor += 8;
        }
        else
        {
            stackReserve = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
            stackCommit  = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
            heapReserve  = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
            heapCommit   = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
        }
        // Older PE optional headers can be truncated before NumberOfRvaAndSizes. Treat missing
        // trailing fields as zero so Win9x / early-NT binaries still parse.
        uint loaderFlags = 0;
        uint numRva = 0;
        if (cursor + 8 <= optSize && cursor + 8 <= span.Length)
        {
            loaderFlags = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
            numRva      = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
        }

        // Cap to a sane upper bound; corrupt headers sometimes claim huge counts.
        if (numRva > 16) numRva = 16;

        var dirs = new DataDirectory[numRva];
        for (int i = 0; i < numRva && cursor + 8 <= optSize && cursor + 8 <= span.Length; i++)
        {
            uint rva  = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(span[cursor..(cursor + 4)]); cursor += 4;
            dirs[i] = new DataDirectory(rva, size);
        }

        return new PEHeaders(machine, numSections, timestamp, symTable, numSyms, optSize, chars, magic,
            majorLinker, minorLinker, sizeOfCode, entry, baseOfCode, imageBase, sectionAlign, fileAlign,
            majorOs, minorOs, majorImage, minorImage, majorSub, minorSub,
            sizeOfImage, sizeOfHeaders, checkSum, subsystem, dllChars,
            stackReserve, stackCommit, heapReserve, heapCommit,
            loaderFlags, numRva, dirs);
    }

    private static List<SectionHeader> ParseSections(byte[] bytes, int offset, ushort count)
    {
        var list = new List<SectionHeader>(count);
        for (int i = 0; i < count; i++)
        {
            int o = offset + i * 40;
            if (o + 40 > bytes.Length)
                throw new InvalidPEException($"Section header #{i} is truncated.");

            string name = Encoding.ASCII.GetString(bytes, o, 8).TrimEnd('\0');
            uint vSize  = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(o + 8, 4));
            uint vAddr  = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(o + 12, 4));
            uint rSize  = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(o + 16, 4));
            uint rPtr   = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(o + 20, 4));
            uint relocs = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(o + 24, 4));
            uint lines  = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(o + 28, 4));
            ushort nRel = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(o + 32, 2));
            ushort nLn  = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(o + 34, 2));
            uint chars  = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(o + 36, 4));

            list.Add(new SectionHeader(name, vSize, vAddr, rSize, rPtr, relocs, lines, nRel, nLn, chars));
        }
        return list;
    }

    // -----------------------------------------------------------------
    //  Byte access helpers
    // -----------------------------------------------------------------

    /// <summary>Raw image bytes (do not mutate).</summary>
    public ReadOnlySpan<byte> RawBytes => _image;

    /// <summary>Converts an RVA into a file offset using the section table.</summary>
    public bool TryRvaToFileOffset(uint rva, out uint fileOffset)
    {
        foreach (var s in Sections)
        {
            uint span = s.VirtualSize == 0 ? s.SizeOfRawData : Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span)
            {
                uint delta = rva - s.VirtualAddress;
                if (delta >= s.SizeOfRawData)
                {
                    fileOffset = 0;
                    return false;
                }
                fileOffset = s.PointerToRawData + delta;
                return fileOffset <= _image.Length;
            }
        }
        fileOffset = 0;
        return false;
    }

    /// <summary>Finds the section that contains <paramref name="rva"/>, or <c>null</c>.</summary>
    public SectionHeader? SectionContaining(uint rva)
    {
        foreach (var s in Sections)
        {
            if (s.ContainsRva(rva)) return s;
        }
        return null;
    }

    /// <summary>Reads a slice of the image's raw bytes at <paramref name="fileOffset"/>.</summary>
    public ReadOnlySpan<byte> SliceAtFileOffset(uint fileOffset, int length)
    {
        if (fileOffset + (uint)length > _image.Length)
            throw new InvalidPEException(
                $"Attempt to read {length} bytes at file offset 0x{fileOffset:X} exceeds image size 0x{_image.Length:X}.");
        return _image.AsSpan((int)fileOffset, length);
    }

    /// <summary>Reads <paramref name="length"/> bytes starting at <paramref name="rva"/>.</summary>
    public bool TryReadAtRva(uint rva, int length, out ReadOnlySpan<byte> bytes)
    {
        if (TryRvaToFileOffset(rva, out uint fo) && fo + (uint)length <= _image.Length)
        {
            bytes = _image.AsSpan((int)fo, length);
            return true;
        }
        bytes = default;
        return false;
    }

    // -----------------------------------------------------------------
    //  Higher-level parsing helpers used by checks
    // -----------------------------------------------------------------

    /// <summary>Parses the load-config directory, if present.</summary>
    public LoadConfig? TryReadLoadConfig()
    {
        var dir = Headers.GetDirectory(PEConstants.DirectoryLoadConfigTable);
        if (dir.IsEmpty) return null;
        if (!TryRvaToFileOffset(dir.RelativeVirtualAddress, out uint fo)) return null;

        // The directory starts with a 32-bit Size field we trust over the directory's reported Size,
        // because some images report Size 0 but still carry a load-config structure.
        if (fo + 4 > _image.Length) return null;
        uint structSize = BinaryPrimitives.ReadUInt32LittleEndian(_image.AsSpan((int)fo, 4));
        uint effectiveSize = Math.Max(structSize, dir.Size);
        if (fo + effectiveSize > _image.Length || effectiveSize < 4) return null;

        var span = _image.AsSpan((int)fo, (int)Math.Min(effectiveSize, 256u));
        return Headers.Is64Bit ? ReadLoadConfig64(span) : ReadLoadConfig32(span);
    }

    private static LoadConfig ReadLoadConfig32(ReadOnlySpan<byte> s)
    {
        uint size = Read32(s, 0);
        uint ts   = Read32(s, 4);
        ushort majV = Read16(s, 8);
        ushort minV = Read16(s, 10);
        uint gClear = Read32(s, 12);
        uint gSet   = Read32(s, 16);
        uint csTo   = Read32(s, 20);
        ulong deBlock = Read32(s, 24);
        ulong deTotal = Read32(s, 28);
        ulong lockTable = Read32(s, 32);
        ulong maxAlloc  = Read32(s, 36);
        ulong vmThresh  = Read32(s, 40);
        ulong affinity  = Read32(s, 44);
        uint heapFlags  = Read32(s, 48);
        ushort csd = Read16(s, 52);
        ushort depLoad = Read16(s, 54);
        ulong edit = Read32(s, 56);
        ulong cookie = Read32(s, 60);
        ulong sehTable = Read32(s, 64);
        ulong sehCount = Read32(s, 68);
        ulong cfCheck = s.Length >= 76 ? Read32(s, 72) : 0;
        ulong cfDispatch = s.Length >= 80 ? Read32(s, 76) : 0;
        ulong cfTable = s.Length >= 84 ? Read32(s, 80) : 0;
        ulong cfCount = s.Length >= 88 ? Read32(s, 84) : 0;
        uint guardFlags = s.Length >= 92 ? Read32(s, 88) : 0;

        return new LoadConfig(size, ts, majV, minV, gClear, gSet, csTo, deBlock, deTotal, lockTable,
            maxAlloc, vmThresh, affinity, heapFlags, csd, depLoad, edit, cookie,
            sehTable, sehCount, cfCheck, cfDispatch, cfTable, cfCount, guardFlags);
    }

    private static LoadConfig ReadLoadConfig64(ReadOnlySpan<byte> s)
    {
        uint size = Read32(s, 0);
        uint ts   = Read32(s, 4);
        ushort majV = Read16(s, 8);
        ushort minV = Read16(s, 10);
        uint gClear = Read32(s, 12);
        uint gSet   = Read32(s, 16);
        uint csTo   = Read32(s, 20);
        ulong deBlock = Read64(s, 24);
        ulong deTotal = Read64(s, 32);
        ulong lockTable = Read64(s, 40);
        ulong maxAlloc  = Read64(s, 48);
        ulong vmThresh  = Read64(s, 56);
        ulong affinity  = Read64(s, 64);
        uint heapFlags  = Read32(s, 72);
        ushort csd = Read16(s, 76);
        ushort depLoad = Read16(s, 78);
        // Layout matches IMAGE_LOAD_CONFIG_DIRECTORY64 from winnt.h.
        ulong edit = Read64(s, 80);
        ulong cookie = Read64(s, 88);
        ulong sehTable = s.Length >= 104 ? Read64(s, 96) : 0;   // unused on x64 but still present
        ulong sehCount = s.Length >= 112 ? Read64(s, 104) : 0;
        ulong cfCheck    = s.Length >= 120 ? Read64(s, 112) : 0;
        ulong cfDispatch = s.Length >= 128 ? Read64(s, 120) : 0;
        ulong cfTable    = s.Length >= 136 ? Read64(s, 128) : 0;
        ulong cfCount    = s.Length >= 144 ? Read64(s, 136) : 0;
        uint guardFlags  = s.Length >= 148 ? Read32(s, 144) : 0;

        return new LoadConfig(size, ts, majV, minV, gClear, gSet, csTo, deBlock, deTotal, lockTable,
            maxAlloc, vmThresh, affinity, heapFlags, csd, depLoad, edit, cookie,
            sehTable, sehCount, cfCheck, cfDispatch, cfTable, cfCount, guardFlags);
    }

    /// <summary>Enumerates the debug directory entries, if present.</summary>
    public IReadOnlyList<DebugEntry> ReadDebugEntries()
    {
        var dir = Headers.GetDirectory(PEConstants.DirectoryDebug);
        if (dir.IsEmpty || !TryRvaToFileOffset(dir.RelativeVirtualAddress, out uint fo))
            return Array.Empty<DebugEntry>();

        const int Size = 28;
        int count = (int)(dir.Size / Size);
        var list = new List<DebugEntry>(count);
        for (int i = 0; i < count; i++)
        {
            uint o = fo + (uint)(i * Size);
            if (o + Size > _image.Length) break;
            var s = _image.AsSpan((int)o, Size);
            list.Add(new DebugEntry(
                Read32(s, 0),
                Read32(s, 4),
                Read16(s, 8),
                Read16(s, 10),
                Read32(s, 12),
                Read32(s, 16),
                Read32(s, 20),
                Read32(s, 24)));
        }
        return list;
    }

    /// <summary>Reads the CodeView (RSDS) PDB info if present in the debug directory.</summary>
    public CodeViewInfo? TryReadCodeView()
    {
        foreach (var d in ReadDebugEntries())
        {
            if (d.Type != PEConstants.DebugTypeCodeview) continue;
            if (d.PointerToRawData == 0 || d.PointerToRawData + d.SizeOfData > _image.Length) continue;
            var span = _image.AsSpan((int)d.PointerToRawData, (int)d.SizeOfData);
            if (span.Length < 24) continue;
            // RSDS magic
            if (!(span[0] == (byte)'R' && span[1] == (byte)'S' && span[2] == (byte)'D' && span[3] == (byte)'S'))
                continue;
            var guid = new Guid(span.Slice(4, 16).ToArray());
            uint age = Read32(span, 20);
            int zero = span[24..].IndexOf((byte)0);
            string pdb = zero < 0
                ? Encoding.UTF8.GetString(span[24..])
                : Encoding.UTF8.GetString(span.Slice(24, zero));
            return new CodeViewInfo(guid, age, pdb);
        }
        return null;
    }

    /// <summary>Reads the standard import directory (not delay imports).</summary>
    public IReadOnlyList<ImportDescriptor> ReadImports()
    {
        var dir = Headers.GetDirectory(PEConstants.DirectoryImportTable);
        if (dir.IsEmpty || !TryRvaToFileOffset(dir.RelativeVirtualAddress, out uint fo))
            return Array.Empty<ImportDescriptor>();

        var list = new List<ImportDescriptor>();
        for (int i = 0; ; i++)
        {
            int o = (int)fo + i * 20;
            if (o + 20 > _image.Length) break;
            var s = _image.AsSpan(o, 20);
            uint oft = Read32(s, 0);
            uint ts  = Read32(s, 4);
            uint fwd = Read32(s, 8);
            uint name = Read32(s, 12);
            uint ft  = Read32(s, 16);

            if (oft == 0 && ts == 0 && fwd == 0 && name == 0 && ft == 0) break; // terminator

            string dllName = TryRvaToFileOffset(name, out uint nameFo) ? ReadCString(nameFo) : "<unknown>";
            var symbols = ReadImportSymbols(oft != 0 ? oft : ft);
            list.Add(new ImportDescriptor(dllName, oft, ft, ts, fwd, symbols));
        }
        return list;
    }

    private IReadOnlyList<ImportedSymbol> ReadImportSymbols(uint thunkRva)
    {
        var syms = new List<ImportedSymbol>();
        if (thunkRva == 0 || !TryRvaToFileOffset(thunkRva, out uint fo)) return syms;

        bool pe32plus = Headers.Is64Bit;
        int stride = pe32plus ? 8 : 4;
        ulong ordinalFlag = pe32plus ? 0x8000000000000000UL : 0x80000000UL;

        for (int i = 0; ; i++)
        {
            long o = fo + (long)i * stride;
            if (o + stride > _image.Length) break;
            ulong value = pe32plus
                ? Read64(_image, (int)o)
                : Read32(_image, (int)o);
            if (value == 0) break;

            if ((value & ordinalFlag) != 0)
            {
                ushort ord = (ushort)(value & 0xFFFF);
                syms.Add(new ImportedSymbol(null, null, ord));
            }
            else
            {
                uint hintNameRva = (uint)(value & 0x7FFFFFFF);
                if (TryRvaToFileOffset(hintNameRva, out uint hnFo) && hnFo + 2 <= _image.Length)
                {
                    ushort hint = Read16(_image, (int)hnFo);
                    string name = ReadCString(hnFo + 2);
                    syms.Add(new ImportedSymbol(name, hint, null));
                }
                else
                {
                    syms.Add(new ImportedSymbol("<unreadable>", null, null));
                }
            }
        }
        return syms;
    }

    /// <summary>Reads the delay-load import directory.</summary>
    public IReadOnlyList<string> ReadDelayLoadDllNames()
    {
        var dir = Headers.GetDirectory(PEConstants.DirectoryDelayImportDescriptor);
        if (dir.IsEmpty || !TryRvaToFileOffset(dir.RelativeVirtualAddress, out uint fo))
            return Array.Empty<string>();

        var list = new List<string>();
        for (int i = 0; ; i++)
        {
            int o = (int)fo + i * 32;
            if (o + 32 > _image.Length) break;
            var s = _image.AsSpan(o, 32);
            uint attrs = Read32(s, 0);
            uint nameRva = Read32(s, 4);
            if (attrs == 0 && nameRva == 0) break;
            if (TryRvaToFileOffset(nameRva, out uint nfo))
            {
                list.Add(ReadCString(nfo));
            }
        }
        return list;
    }

    /// <summary>Reads and decodes the "Rich" header injected by the Microsoft linker.</summary>
    public RichHeader? TryReadRichHeader()
    {
        // The Rich header lives between the DOS stub and the PE header, ending with "Rich" + XOR key.
        int peOffset = (int)PeHeaderFileOffset;
        if (peOffset < 128 || peOffset > _image.Length) return null;

        var scanRegion = _image.AsSpan(0, peOffset);

        // Find the "Rich" marker scanning backwards.
        int richIndex = -1;
        for (int i = scanRegion.Length - 8; i >= 0x80; i--)
        {
            if (scanRegion[i] == (byte)'R' && scanRegion[i + 1] == (byte)'i' &&
                scanRegion[i + 2] == (byte)'c' && scanRegion[i + 3] == (byte)'h')
            {
                richIndex = i;
                break;
            }
        }
        if (richIndex < 0 || richIndex + 8 > scanRegion.Length) return null;

        uint xorKey = BinaryPrimitives.ReadUInt32LittleEndian(scanRegion.Slice(richIndex + 4, 4));

        // Walk backwards looking for "DanS" ^ xorKey.
        uint danS = 0x536E6144 ^ xorKey;
        int start = -1;
        for (int i = richIndex - 4; i >= 0; i -= 4)
        {
            uint v = BinaryPrimitives.ReadUInt32LittleEndian(scanRegion.Slice(i, 4));
            if (v == danS) { start = i; break; }
        }
        if (start < 0) return null;

        // Entries: start + 16 (skip DanS + three pad dwords) up to richIndex, in 8-byte records.
        var entries = new List<RichEntry>();
        for (int i = start + 16; i + 8 <= richIndex; i += 8)
        {
            uint compId = BinaryPrimitives.ReadUInt32LittleEndian(scanRegion.Slice(i, 4)) ^ xorKey;
            uint count  = BinaryPrimitives.ReadUInt32LittleEndian(scanRegion.Slice(i + 4, 4)) ^ xorKey;
            ushort prodId = (ushort)(compId >> 16);
            ushort build  = (ushort)(compId & 0xFFFF);
            entries.Add(new RichEntry(prodId, build, count));
        }
        return new RichHeader(xorKey, entries);
    }

    // -----------------------------------------------------------------
    //  Primitive readers
    // -----------------------------------------------------------------

    private static ushort Read16(ReadOnlySpan<byte> s, int off) =>
        BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(off, 2));

    private static uint Read32(ReadOnlySpan<byte> s, int off) =>
        BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(off, 4));

    private static ulong Read64(ReadOnlySpan<byte> s, int off) =>
        BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(off, 8));

    private static uint Read32(byte[] b, int off) =>
        BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(off, 4));

    private static ulong Read64(byte[] b, int off) =>
        BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(off, 8));

    private static ushort Read16(byte[] b, int off) =>
        BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(off, 2));

    private string ReadCString(uint fileOffset)
    {
        int start = (int)fileOffset;
        int end = Array.IndexOf(_image, (byte)0, start);
        if (end < 0) end = _image.Length;
        int len = Math.Min(end - start, 512);
        return Encoding.ASCII.GetString(_image, start, len);
    }
}

/// <summary>Thrown by <see cref="PEFile.Load"/> and <see cref="PEFile.Parse"/> for malformed inputs.</summary>
public sealed class InvalidPEException : Exception
{
    public InvalidPEException(string message) : base(message) { }
    public InvalidPEException(string message, Exception inner) : base(message, inner) { }
}
