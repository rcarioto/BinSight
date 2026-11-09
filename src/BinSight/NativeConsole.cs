using System.Runtime.InteropServices;
using System.Text;

namespace BinSight;

/// <summary>
/// Console helpers for the hybrid GUI/CLI binary (console subsystem).
/// CLI relies on the normal console; GUI detaches so Explorer/cmd are not left wedged.
/// </summary>
internal static class NativeConsole
{
    public static void PreferUtf8()
    {
        try
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;
        }
        catch
        {
            // Some host consoles reject encoding changes.
        }
    }

    /// <summary>True when this process currently owns/has a console window.</summary>
    public static bool HasConsoleWindow() =>
        OperatingSystem.IsWindows() && GetConsoleWindow() != IntPtr.Zero;

    /// <summary>
    /// True when another process (typically cmd/PowerShell) shares this console.
    /// Used to decide whether launching the GUI should re-spawn detached so the shell
    /// gets its prompt back immediately.
    /// </summary>
    public static bool SharesConsoleWithParent()
    {
        if (!OperatingSystem.IsWindows() || !HasConsoleWindow())
            return false;

        uint[] pids = new uint[16];
        uint count = GetConsoleProcessList(pids, (uint)pids.Length);
        return count > 1;
    }

    /// <summary>Detach from the console so a WinForms UI does not keep a black console box open.</summary>
    public static void Detach()
    {
        if (!OperatingSystem.IsWindows())
            return;

        try { Console.Out.Flush(); } catch { /* ignore */ }
        try { Console.Error.Flush(); } catch { /* ignore */ }
        FreeConsole();
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList(uint[] processList, uint processCount);
}
