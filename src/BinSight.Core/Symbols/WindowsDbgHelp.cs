using System.Runtime.InteropServices;
using System.Text;

namespace BinSight.Core.Symbols;

/// <summary>
/// Optional Windows DbgHelp-backed symbol lookup for named SafeSEH handlers and
/// nearest-function attribution. No-ops on non-Windows hosts.
/// </summary>
internal static class WindowsDbgHelp
{
    private static readonly object Gate = new();
    private static IntPtr _process;
    private static ulong _moduleBase;
    private static bool _ready;

    public static bool TryLoadModule(string pePath, string? symbolSearchPath, out string? error)
    {
        error = null;
        if (!OperatingSystem.IsWindows())
        {
            error = "DbgHelp is Windows-only.";
            return false;
        }

        lock (Gate)
        {
            ShutdownUnlocked();
            _process = GetCurrentProcess();
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
            string? search = BuildSearchPath(pePath, symbolSearchPath);
            if (!SymInitialize(_process, search, fInvadeProcess: false))
            {
                error = $"SymInitialize failed (err={Marshal.GetLastWin32Error()}).";
                _process = IntPtr.Zero;
                return false;
            }

            _moduleBase = SymLoadModuleEx(_process, IntPtr.Zero, pePath, null, 0, 0, IntPtr.Zero, 0);
            if (_moduleBase == 0)
            {
                error = $"SymLoadModuleEx failed (err={Marshal.GetLastWin32Error()}).";
                SymCleanup(_process);
                _process = IntPtr.Zero;
                return false;
            }

            _ready = true;
            return true;
        }
    }

    public static string? TryNameFromRva(uint rva)
    {
        if (!_ready || _process == IntPtr.Zero || _moduleBase == 0) return null;
        ulong addr = _moduleBase + rva;

        int headerSize = Marshal.SizeOf<SYMBOL_INFO>();
        int total = headerSize + MaxNameBytes;
        IntPtr buffer = Marshal.AllocHGlobal(total);
        try
        {
            for (int i = 0; i < total; i++) Marshal.WriteByte(buffer, i, 0);
            var info = new SYMBOL_INFO
            {
                SizeOfStruct = (uint)headerSize,
                MaxNameLen = MaxNameChars,
            };
            Marshal.StructureToPtr(info, buffer, false);

            if (!SymFromAddr(_process, addr, out _, buffer))
                return null;

            // Name is a flexible array starting at the Name field offset.
            int nameOffset = (int)Marshal.OffsetOf<SYMBOL_INFO>(nameof(SYMBOL_INFO.Name));
            return Marshal.PtrToStringAnsi(buffer + nameOffset);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static bool TryFindSymbolRva(string name, out uint rva)
    {
        rva = 0;
        if (!_ready || _process == IntPtr.Zero || _moduleBase == 0) return false;

        int headerSize = Marshal.SizeOf<SYMBOL_INFO>();
        int total = headerSize + MaxNameBytes;
        IntPtr buffer = Marshal.AllocHGlobal(total);
        try
        {
            for (int i = 0; i < total; i++) Marshal.WriteByte(buffer, i, 0);
            var info = new SYMBOL_INFO
            {
                SizeOfStruct = (uint)headerSize,
                MaxNameLen = MaxNameChars,
            };
            Marshal.StructureToPtr(info, buffer, false);
            if (!SymFromName(_process, name, buffer))
                return false;
            var result = Marshal.PtrToStructure<SYMBOL_INFO>(buffer);
            if (result.Address < _moduleBase) return false;
            rva = (uint)(result.Address - _moduleBase);
            return rva != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static void Shutdown()
    {
        lock (Gate) ShutdownUnlocked();
    }

    private static void ShutdownUnlocked()
    {
        if (_process != IntPtr.Zero)
        {
            try { SymCleanup(_process); } catch { /* ignore */ }
        }
        _process = IntPtr.Zero;
        _moduleBase = 0;
        _ready = false;
    }

    private static string? BuildSearchPath(string pePath, string? symbolSearchPath)
    {
        var parts = new List<string>();
        string? dir = Path.GetDirectoryName(Path.GetFullPath(pePath));
        if (!string.IsNullOrWhiteSpace(dir)) parts.Add(dir!);
        if (!string.IsNullOrWhiteSpace(symbolSearchPath))
        {
            foreach (var p in symbolSearchPath.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                parts.Add(p);
        }
        return parts.Count == 0 ? null : string.Join(";", parts);
    }

    private const int MaxNameChars = 1024;
    private const int MaxNameBytes = MaxNameChars; // ANSI
    private const uint SYMOPT_UNDNAME = 0x00000002;
    private const uint SYMOPT_DEFERRED_LOADS = 0x00000004;
    private const uint SYMOPT_LOAD_LINES = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct SYMBOL_INFO
    {
        public uint SizeOfStruct;
        public uint TypeIndex;
        public ulong Reserved0;
        public ulong Reserved1;
        public uint Index;
        public uint Size;
        public ulong ModBase;
        public uint Flags;
        public ulong Value;
        public ulong Address;
        public uint Register;
        public uint Scope;
        public uint Tag;
        public uint NameLen;
        public uint MaxNameLen;
        public byte Name;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint SymSetOptions(uint SymOptions);

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SymInitialize(IntPtr hProcess, string? UserSearchPath, bool fInvadeProcess);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool SymCleanup(IntPtr hProcess);

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern ulong SymLoadModuleEx(
        IntPtr hProcess, IntPtr hFile, string ImageName, string? ModuleName,
        ulong BaseOfDll, uint DllSize, IntPtr Data, uint Flags);

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern bool SymFromAddr(IntPtr hProcess, ulong Address, out ulong Displacement, IntPtr Symbol);

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern bool SymFromName(IntPtr hProcess, string Name, IntPtr Symbol);
}
