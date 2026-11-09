namespace BinSight.Core.PE;

/// <summary>
/// Well-known PE/COFF constants. Mirrors values from <c>winnt.h</c>.
/// </summary>
public static class PEConstants
{
    // DOS / NT header magic
    public const ushort DosMagic = 0x5A4D;          // 'MZ'
    public const uint   NtSignature = 0x00004550;   // 'PE\0\0'

    // Optional header magic
    public const ushort OptionalHeaderMagicPe32  = 0x010B;
    public const ushort OptionalHeaderMagicPe32Plus = 0x020B;

    // Image file machine
    public const ushort MachineI386  = 0x014C;
    public const ushort MachineAmd64 = 0x8664;
    public const ushort MachineArm   = 0x01C0;
    public const ushort MachineArm64 = 0xAA64;
    public const ushort MachineIa64  = 0x0200;

    // File characteristics
    public const ushort FileRelocsStripped  = 0x0001;
    public const ushort FileExecutableImage = 0x0002;
    public const ushort FileLineNumsStripped = 0x0004;
    public const ushort FileLocalSymsStripped = 0x0008;
    public const ushort FileAggressiveWsTrim = 0x0010;
    public const ushort FileLargeAddressAware = 0x0020;
    public const ushort FileBytesReversedLo = 0x0080;
    public const ushort File32BitMachine    = 0x0100;
    public const ushort FileDebugStripped   = 0x0200;
    public const ushort FileRemovableRunFromSwap = 0x0400;
    public const ushort FileNetRunFromSwap  = 0x0800;
    public const ushort FileSystem          = 0x1000;
    public const ushort FileDll             = 0x2000;
    public const ushort FileUpSystemOnly    = 0x4000;

    // Extended DLL characteristics (IMAGE_DLLCHARACTERISTICS_EX_*), stored in
    // IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS debug directory payload.
    public const uint ExDllCharCetCompat = 0x0001;
    public const uint ExDllCharCetCompatStrictMode = 0x0002;
    public const uint ExDllCharCetSetContextIpValidationRelaxedMode = 0x0004;
    public const uint ExDllCharCetDynamicApisAllowInProc = 0x0008;
    public const uint ExDllCharCetReserved1 = 0x0010;
    public const uint ExDllCharHotpatchCompatible = 0x0040;

    /// <summary>Used by some toolsets for Spectre/volatile metadata sidecars.</summary>
    public const uint DebugTypeExtended = 21;

    // Additional GuardFlags
    public const uint GuardEhContinuationTablePresent = 0x00400000;
    public const uint GuardXfgEnabled = 0x00800000;
    public const uint GuardXfgCastGuard = 0x01000000;

    // DllCharacteristics (mirrors IMAGE_DLLCHARACTERISTICS_*)
    public const ushort DllCharHighEntropyVa    = 0x0020;
    public const ushort DllCharDynamicBase      = 0x0040;
    public const ushort DllCharForceIntegrity   = 0x0080;
    public const ushort DllCharNxCompat         = 0x0100;
    public const ushort DllCharNoIsolation      = 0x0200;
    public const ushort DllCharNoSeh            = 0x0400;
    public const ushort DllCharNoBind           = 0x0800;
    public const ushort DllCharAppContainer     = 0x1000;
    public const ushort DllCharWdmDriver        = 0x2000;
    public const ushort DllCharGuardCf          = 0x4000;
    public const ushort DllCharTerminalServerAware = 0x8000;

    // Section flags (IMAGE_SCN_*)
    public const uint SectionMemExecute = 0x20000000;
    public const uint SectionMemRead    = 0x40000000;
    public const uint SectionMemWrite   = 0x80000000;
    public const uint SectionMemShared  = 0x10000000;
    public const uint SectionCntCode    = 0x00000020;

    // Data directory indices
    public const int DirectoryExportTable          = 0;
    public const int DirectoryImportTable          = 1;
    public const int DirectoryResourceTable        = 2;
    public const int DirectoryExceptionTable       = 3;
    public const int DirectoryCertificateTable     = 4;
    public const int DirectoryBaseRelocationTable  = 5;
    public const int DirectoryDebug                = 6;
    public const int DirectoryArchitecture         = 7;
    public const int DirectoryGlobalPtr            = 8;
    public const int DirectoryTlsTable             = 9;
    public const int DirectoryLoadConfigTable      = 10;
    public const int DirectoryBoundImport          = 11;
    public const int DirectoryImportAddressTable   = 12;
    public const int DirectoryDelayImportDescriptor = 13;
    public const int DirectoryClrRuntimeHeader     = 14;

    // Debug types
    public const uint DebugTypeUnknown       = 0;
    public const uint DebugTypeCoff          = 1;
    public const uint DebugTypeCodeview      = 2;
    public const uint DebugTypeFpo           = 3;
    public const uint DebugTypeMisc          = 4;
    public const uint DebugTypeException     = 5;
    public const uint DebugTypeFixup         = 6;
    public const uint DebugTypeOmapToSrc     = 7;
    public const uint DebugTypeOmapFromSrc   = 8;
    public const uint DebugTypeBorland       = 9;
    public const uint DebugTypeReserved10    = 10;
    public const uint DebugTypeClsid         = 11;
    public const uint DebugTypeVcFeature     = 12;
    public const uint DebugTypePogo          = 13;
    public const uint DebugTypeIltcg         = 14;
    public const uint DebugTypeMpx           = 15;
    public const uint DebugTypeRepro         = 16;
    public const uint DebugTypeExDllCharacteristics = 20;

    // Guard flags (IMAGE_GUARD_*)
    public const uint GuardCfInstrumented        = 0x00000100;
    public const uint GuardCfWInstrumented       = 0x00000200;
    public const uint GuardCfFunctionTablePresent = 0x00000400;
    public const uint GuardSecurityCookieUnused  = 0x00000800;
    public const uint GuardProtectDelayLoadIat   = 0x00001000;
    public const uint GuardDelayLoadIatInOwnSection = 0x00002000;
    public const uint GuardCfExportSuppressionInfoPresent = 0x00004000;
    public const uint GuardCfEnableExportSuppression = 0x00008000;
    public const uint GuardCfLongJumpTablePresent = 0x00010000;
    public const uint GuardRfInstrumented        = 0x00020000;
    public const uint GuardRfEnable              = 0x00040000;
    public const uint GuardRfStrict              = 0x00080000;

    // Subsystem
    public const ushort SubsystemNative        = 1;
    public const ushort SubsystemWindowsGui    = 2;
    public const ushort SubsystemWindowsCui    = 3;
    public const ushort SubsystemOs2Cui        = 5;
    public const ushort SubsystemPosixCui      = 7;
    public const ushort SubsystemWindowsCeGui  = 9;
    public const ushort SubsystemEfiApplication = 10;
    public const ushort SubsystemEfiBootServiceDriver = 11;
    public const ushort SubsystemEfiRuntimeDriver = 12;
    public const ushort SubsystemEfiRom        = 13;
    public const ushort SubsystemXbox          = 14;
    public const ushort SubsystemWindowsBootApplication = 16;
}
