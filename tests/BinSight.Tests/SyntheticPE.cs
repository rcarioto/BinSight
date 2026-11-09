using System.Buffers.Binary;
using System.Text;
using BinSight.Core.PE;

namespace BinSight.Tests;

/// <summary>
/// Builds a minimal, well-formed PE image in memory so that checks can be exercised without
/// shipping binary test artifacts. The image is not loadable by the OS, but every header field
/// used by BinSight is populated at the right offset.
/// </summary>
public sealed class SyntheticPE
{
    private uint _syntheticRelocRva;
    private uint _syntheticRelocSize;

    public bool Is64Bit { get; set; }
    public ushort Machine { get; set; } = PEConstants.MachineI386;
    public ushort DllCharacteristics { get; set; } =
        PEConstants.DllCharDynamicBase | PEConstants.DllCharNxCompat;
    public ushort FileCharacteristics { get; set; } = PEConstants.FileExecutableImage;
    public ulong ImageBase { get; set; } = 0x00400000;
    public byte MajorLinkerVersion { get; set; } = 14;
    public byte MinorLinkerVersion { get; set; } = 30;
    public List<SyntheticSection> Sections { get; } = new();
    public List<SyntheticImport> Imports { get; } = new();
    public SyntheticLoadConfig? LoadConfig { get; set; }
    public byte[]? SecurityCookieValue { get; set; }  // optional, placed in .rdata

    public static SyntheticPE NewHealthyPE32() => new()
    {
        Is64Bit = false,
        Machine = PEConstants.MachineI386,
        FileCharacteristics = (ushort)(PEConstants.FileExecutableImage | PEConstants.FileDll | PEConstants.File32BitMachine),
        DllCharacteristics = (ushort)(PEConstants.DllCharDynamicBase | PEConstants.DllCharNxCompat | PEConstants.DllCharNoSeh),
        Sections =
        {
            new SyntheticSection(".text",  PEConstants.SectionMemRead | PEConstants.SectionMemExecute | PEConstants.SectionCntCode),
            new SyntheticSection(".rdata", PEConstants.SectionMemRead),
            new SyntheticSection(".data",  PEConstants.SectionMemRead | PEConstants.SectionMemWrite),
        },
        Imports = { new SyntheticImport("KERNEL32.dll", new[] { "QueryPerformanceCounter" }) },
    };

    public static SyntheticPE NewHealthyPE32Plus() => new()
    {
        Is64Bit = true,
        Machine = PEConstants.MachineAmd64,
        FileCharacteristics = (ushort)(PEConstants.FileExecutableImage | PEConstants.FileDll),
        DllCharacteristics = (ushort)(PEConstants.DllCharDynamicBase | PEConstants.DllCharNxCompat | PEConstants.DllCharHighEntropyVa | PEConstants.DllCharGuardCf),
        ImageBase = 0x0000000140000000,
        Sections =
        {
            new SyntheticSection(".text",  PEConstants.SectionMemRead | PEConstants.SectionMemExecute | PEConstants.SectionCntCode),
            new SyntheticSection(".rdata", PEConstants.SectionMemRead),
            new SyntheticSection(".data",  PEConstants.SectionMemRead | PEConstants.SectionMemWrite),
        },
        Imports = { new SyntheticImport("KERNEL32.dll", new[] { "QueryPerformanceCounter" }) },
        LoadConfig = new SyntheticLoadConfig { HasSecurityCookie = true, GuardCfCheckFunction = 0x1000 },
    };

    public byte[] Build()
    {
        bool plus = Is64Bit;
        const int SectionAlign = 0x1000;
        const int FileAlign    = 0x200;
        const int DosStubLen   = 0x80;

        // Lay out section data first so we can compute the final file size.
        // Each section payload holds: imports (if assigned to it) and load config.
        var sectionPayloads = Sections.Select(_ => new MemoryStream()).ToList();

        // Import directory lives in the last section whose name is ".rdata" (or last section if none).
        int importSectionIndex = Sections.FindIndex(s => s.Name == ".rdata");
        if (importSectionIndex < 0) importSectionIndex = Sections.Count - 1;

        int loadConfigSectionIndex = importSectionIndex; // same section is fine

        // Pre-compute layout
        int numSections = Sections.Count;
        int optionalHeaderSize = plus ? 240 : 224;
        int numRvaAndSizes = 16;
        int sectionHeadersSize = numSections * 40;
        int peHeadersSize = 4 /*sig*/ + 20 /*coff*/ + optionalHeaderSize + sectionHeadersSize;
        int headersTotal = DosStubLen + peHeadersSize;
        uint sizeOfHeaders = (uint)AlignUp(headersTotal, FileAlign);

        // Assign VAs and raw pointers.
        uint curVa = (uint)SectionAlign;
        uint curRaw = sizeOfHeaders;
        var sectionMeta = new List<SectionLayout>();
        foreach (var s in Sections)
        {
            sectionMeta.Add(new SectionLayout
            {
                Name = s.Name,
                Characteristics = s.Characteristics,
                VirtualAddress = curVa,
                PointerToRawData = curRaw,
            });
            curVa  = (uint)AlignUp((int)curVa + 0x1000, SectionAlign);
            curRaw = (uint)AlignUp((int)curRaw + FileAlign, FileAlign);
        }

        // Build payload of the import section.
        var importSection = sectionPayloads[importSectionIndex];
        uint importSectionVa = sectionMeta[importSectionIndex].VirtualAddress;

        // Layout inside the section (offsets from VA of that section):
        //   [IMAGE_IMPORT_DESCRIPTOR[]] [DLL name strings] [IMAGE_THUNK_DATA[]] [HINT/NAME]
        uint importDirRva = 0;
        uint iatRva = 0;
        uint loadConfigRva = 0;
        uint securityCookieRva = 0;

        {
            int idtSize = (Imports.Count + 1) * 20;
            var buf = new List<byte>();
            // Reserve IDT area, fill later.
            buf.AddRange(new byte[idtSize]);

            // Reserve thunks (OriginalFirstThunk & FirstThunk).
            int thunkStride = plus ? 8 : 4;
            var thunkOffsets = new int[Imports.Count * 2];
            for (int i = 0; i < Imports.Count; i++)
            {
                // Each list is terminated by a zero thunk.
                int oftOff = buf.Count;
                buf.AddRange(new byte[(Imports[i].Symbols.Count + 1) * thunkStride]);
                int ftOff  = buf.Count;
                buf.AddRange(new byte[(Imports[i].Symbols.Count + 1) * thunkStride]);
                thunkOffsets[i * 2] = oftOff;
                thunkOffsets[i * 2 + 1] = ftOff;
            }

            // Write DLL names.
            var dllNameOffsets = new int[Imports.Count];
            for (int i = 0; i < Imports.Count; i++)
            {
                dllNameOffsets[i] = buf.Count;
                buf.AddRange(Encoding.ASCII.GetBytes(Imports[i].DllName));
                buf.Add(0);
            }

            // Write Hint/Name records and fill thunks.
            for (int i = 0; i < Imports.Count; i++)
            {
                int oftOff = thunkOffsets[i * 2];
                int ftOff  = thunkOffsets[i * 2 + 1];
                var syms = Imports[i].Symbols;
                for (int j = 0; j < syms.Count; j++)
                {
                    int hnOff = buf.Count;
                    buf.AddRange(new byte[2]); // hint = 0
                    buf.AddRange(Encoding.ASCII.GetBytes(syms[j]));
                    buf.Add(0);
                    if ((buf.Count & 1) == 1) buf.Add(0);

                    uint hnRva = importSectionVa + (uint)hnOff;
                    WriteThunk(buf, oftOff + j * thunkStride, hnRva, plus);
                    WriteThunk(buf, ftOff  + j * thunkStride, hnRva, plus);
                }
            }

            // Fill IDT.
            for (int i = 0; i < Imports.Count; i++)
            {
                int o = i * 20;
                WriteU32(buf, o + 0, importSectionVa + (uint)thunkOffsets[i * 2]);     // OriginalFirstThunk
                WriteU32(buf, o + 4, 0);                                               // TimeDateStamp
                WriteU32(buf, o + 8, 0);                                               // ForwarderChain
                WriteU32(buf, o + 12, importSectionVa + (uint)dllNameOffsets[i]);      // Name
                WriteU32(buf, o + 16, importSectionVa + (uint)thunkOffsets[i * 2 + 1]);// FirstThunk
            }
            // Terminator is already zero-initialized.

            importDirRva = Imports.Count > 0 ? importSectionVa : 0;
            iatRva = Imports.Count > 0 ? importSectionVa + (uint)thunkOffsets[1] : 0;

            // Append Load Config (if any) to same section, aligned.
            if (LoadConfig is not null)
            {
                while ((buf.Count & 7) != 0) buf.Add(0);
                loadConfigRva = importSectionVa + (uint)buf.Count;
                buf.AddRange(BuildLoadConfigBytes(plus));

                if (LoadConfig.HasSecurityCookie)
                {
                    // Place a real cookie slot so DefaultGSCookieCheck can read it.
                    byte[] cookieBytes = SecurityCookieValue ??
                        (plus
                            ? BitConverter.GetBytes(0x1122334455667788UL)
                            : BitConverter.GetBytes(0x11223344U));

                    while ((buf.Count & 7) != 0) buf.Add(0);
                    securityCookieRva = importSectionVa + (uint)buf.Count;
                    buf.AddRange(cookieBytes);

                    // Patch the Load Config's SecurityCookie field to point at our bytes (VA).
                    ulong va = ImageBase + securityCookieRva;
                    int sizeOfField = plus ? 8 : 4;
                    int sizeOfCookiePointerOffsetInLc = plus ? 88 : 60;
                    for (int b = 0; b < sizeOfField; b++)
                        buf[(int)(loadConfigRva - importSectionVa) + sizeOfCookiePointerOffsetInLc + b] = (byte)(va >> (8 * b));
                }
            }

            // Minimal base relocation block so RelocsStrippedCheck can pass healthy images.
            while ((buf.Count & 3) != 0) buf.Add(0);
            uint relocRva = importSectionVa + (uint)buf.Count;
            // IMAGE_BASE_RELOCATION: VirtualAddress, SizeOfBlock, one HIGHLOW/DIR64 entry, pad.
            buf.AddRange(BitConverter.GetBytes(sectionMeta[0].VirtualAddress)); // Page RVA (.text)
            buf.AddRange(BitConverter.GetBytes(12u)); // SizeOfBlock
            buf.AddRange(BitConverter.GetBytes((ushort)((plus ? 10 : 3) << 12))); // type << 12 | offset 0
            buf.AddRange(new byte[2]); // pad to 4
            // Stash reloc RVA/size via fields written after we know them — use local captured below.
            _syntheticRelocRva = relocRva;
            _syntheticRelocSize = 12;

            importSection.Write(buf.ToArray(), 0, buf.Count);
        }

        // Compose file.
        var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);

        // DOS header
        bw.Write((ushort)PEConstants.DosMagic);
        bw.Write(new byte[0x3A]);
        bw.Write((uint)DosStubLen);               // e_lfanew at 0x3C
        // Pad to DosStubLen
        while (ms.Position < DosStubLen) bw.Write((byte)0);

        // PE signature
        bw.Write(PEConstants.NtSignature);

        // COFF header
        bw.Write(Machine);
        bw.Write((ushort)numSections);
        bw.Write((uint)0);           // timestamp
        bw.Write((uint)0);           // sym table
        bw.Write((uint)0);           // num syms
        bw.Write((ushort)optionalHeaderSize);
        bw.Write(FileCharacteristics);

        // Optional header
        bw.Write(plus ? PEConstants.OptionalHeaderMagicPe32Plus : PEConstants.OptionalHeaderMagicPe32);
        bw.Write(MajorLinkerVersion);
        bw.Write(MinorLinkerVersion);
        bw.Write((uint)0x1000);      // SizeOfCode
        bw.Write((uint)0x1000);      // SizeOfInitData
        bw.Write((uint)0);           // SizeOfUninitData
        bw.Write((uint)0x1000);      // AddressOfEntryPoint
        bw.Write((uint)0x1000);      // BaseOfCode
        if (!plus) bw.Write((uint)0x2000); // BaseOfData (PE32 only)
        if (plus) bw.Write(ImageBase); else bw.Write((uint)ImageBase);
        bw.Write((uint)SectionAlign);
        bw.Write((uint)FileAlign);
        bw.Write((ushort)6); bw.Write((ushort)0); // OS version
        bw.Write((ushort)0); bw.Write((ushort)0); // image version
        bw.Write((ushort)6); bw.Write((ushort)0); // subsystem version
        bw.Write((uint)0);                        // Win32VersionValue
        bw.Write((uint)(curRaw));                 // SizeOfImage (rough)
        bw.Write(sizeOfHeaders);                  // SizeOfHeaders
        bw.Write((uint)0);                        // CheckSum
        bw.Write((ushort)3);                      // Subsystem (CUI)
        bw.Write(DllCharacteristics);
        if (plus)
        {
            bw.Write((ulong)0x100000); bw.Write((ulong)0x1000);
            bw.Write((ulong)0x100000); bw.Write((ulong)0x1000);
        }
        else
        {
            bw.Write((uint)0x100000); bw.Write((uint)0x1000);
            bw.Write((uint)0x100000); bw.Write((uint)0x1000);
        }
        bw.Write((uint)0);                        // LoaderFlags
        bw.Write((uint)numRvaAndSizes);

        var directories = new (uint rva, uint size)[numRvaAndSizes];
        if (importDirRva != 0)
        {
            directories[PEConstants.DirectoryImportTable] = (importDirRva, (uint)((Imports.Count + 1) * 20));
            if (iatRva != 0)
                directories[PEConstants.DirectoryImportAddressTable] = (iatRva, (uint)(Imports.Sum(i => (i.Symbols.Count + 1)) * (plus ? 8 : 4)));
        }
        if (loadConfigRva != 0)
            directories[PEConstants.DirectoryLoadConfigTable] = (loadConfigRva, plus ? 148u : 92u);
        if (_syntheticRelocSize != 0)
            directories[PEConstants.DirectoryBaseRelocationTable] = (_syntheticRelocRva, _syntheticRelocSize);

        for (int i = 0; i < numRvaAndSizes; i++)
        {
            bw.Write(directories[i].rva);
            bw.Write(directories[i].size);
        }

        // Section headers
        for (int i = 0; i < numSections; i++)
        {
            var m = sectionMeta[i];
            var nameBytes = new byte[8];
            var nb = Encoding.ASCII.GetBytes(m.Name);
            Array.Copy(nb, nameBytes, Math.Min(nb.Length, 8));
            bw.Write(nameBytes);
            bw.Write((uint)0x1000);              // VirtualSize
            bw.Write(m.VirtualAddress);
            uint rawSize = (uint)Math.Max(FileAlign, AlignUp((int)sectionPayloads[i].Length, FileAlign));
            bw.Write(rawSize);
            bw.Write(m.PointerToRawData);
            bw.Write((uint)0); bw.Write((uint)0);
            bw.Write((ushort)0); bw.Write((ushort)0);
            bw.Write(m.Characteristics);
        }

        // Pad to end of headers
        while (ms.Position < sizeOfHeaders) bw.Write((byte)0);

        // Section payloads
        for (int i = 0; i < numSections; i++)
        {
            var m = sectionMeta[i];
            while (ms.Position < m.PointerToRawData) bw.Write((byte)0);
            var data = sectionPayloads[i].ToArray();
            bw.Write(data);
            uint rawSize = (uint)Math.Max(FileAlign, AlignUp(data.Length, FileAlign));
            while (ms.Position < m.PointerToRawData + rawSize) bw.Write((byte)0);
        }

        return ms.ToArray();
    }

    private byte[] BuildLoadConfigBytes(bool plus)
    {
        // Layout follows IMAGE_LOAD_CONFIG_DIRECTORY{32,64}. Only fields we assert on are meaningful.
        if (plus)
        {
            // Size through GuardFlags (offset 144 + 4).
            byte[] lc = new byte[148];
            BinaryPrimitives.WriteUInt32LittleEndian(lc.AsSpan(0, 4), (uint)lc.Length);
            // SecurityCookie VA is patched later once cookie bytes are placed.
            BinaryPrimitives.WriteUInt64LittleEndian(lc.AsSpan(112, 8), LoadConfig!.GuardCfCheckFunction);
            BinaryPrimitives.WriteUInt32LittleEndian(lc.AsSpan(144, 4), LoadConfig.GuardFlags);
            return lc;
        }
        else
        {
            // Size through GuardFlags (offset 88 + 4).
            byte[] lc = new byte[92];
            BinaryPrimitives.WriteUInt32LittleEndian(lc.AsSpan(0, 4), (uint)lc.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(lc.AsSpan(64, 4), (uint)LoadConfig!.SafeSehTable);
            BinaryPrimitives.WriteUInt32LittleEndian(lc.AsSpan(68, 4), (uint)LoadConfig.SafeSehCount);
            BinaryPrimitives.WriteUInt32LittleEndian(lc.AsSpan(72, 4), (uint)LoadConfig.GuardCfCheckFunction);
            BinaryPrimitives.WriteUInt32LittleEndian(lc.AsSpan(88, 4), LoadConfig.GuardFlags);
            return lc;
        }
    }

    private static int AlignUp(int value, int alignment) =>
        (value + alignment - 1) & ~(alignment - 1);

    private static void WriteU32(List<byte> buf, int offset, uint value)
    {
        buf[offset + 0] = (byte)(value & 0xFF);
        buf[offset + 1] = (byte)((value >> 8) & 0xFF);
        buf[offset + 2] = (byte)((value >> 16) & 0xFF);
        buf[offset + 3] = (byte)((value >> 24) & 0xFF);
    }

    private static void WriteThunk(List<byte> buf, int offset, uint rva, bool plus)
    {
        if (plus)
        {
            ulong v = rva;
            for (int i = 0; i < 8; i++) buf[offset + i] = (byte)(v >> (8 * i));
        }
        else
        {
            uint v = rva;
            for (int i = 0; i < 4; i++) buf[offset + i] = (byte)(v >> (8 * i));
        }
    }

    private sealed class SectionLayout
    {
        public string Name = "";
        public uint Characteristics;
        public uint VirtualAddress;
        public uint PointerToRawData;
    }
}

public sealed record SyntheticSection(string Name, uint Characteristics);

public sealed class SyntheticImport
{
    public SyntheticImport(string dll, IEnumerable<string> symbols)
    {
        DllName = dll;
        Symbols = symbols.ToList();
    }
    public string DllName { get; }
    public List<string> Symbols { get; }
}

public sealed class SyntheticLoadConfig
{
    public bool HasSecurityCookie { get; set; } = true;
    public ulong GuardCfCheckFunction { get; set; } = 0;
    public uint GuardFlags { get; set; } = 0;
    public ulong SafeSehTable { get; set; } = 0;
    public ulong SafeSehCount { get; set; } = 0;
}
