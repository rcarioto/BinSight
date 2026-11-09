using System.Diagnostics;
using System.Text;

namespace BinSight;

/// <summary>
/// Single entry point: double-click / no args / <c>/gui</c> opens the WinForms UI;
/// any other CLI switches run the scanner on the console.
/// </summary>
/// <remarks>
/// Built as a console-subsystem app so cmd/PowerShell wait for CLI scans and restore
/// the prompt under the output. GUI launches detach from the console (and re-spawn
/// when started from a shared shell) so the prompt is not left wedged.
/// </remarks>
internal static class Program
{
    /// <summary>Private switch: this process is the detached GUI worker (do not re-spawn).</summary>
    internal const string GuiHostSwitch = "internal-gui-host";

    [STAThread]
    private static int Main(string[] args)
    {
        if (ShouldLaunchGui(args, out string? initialPath, out string? initialProfile, out bool isGuiHost))
            return LaunchGui(initialPath, initialProfile, isGuiHost);

        // CLI: console subsystem means the parent shell waits for us; prompt returns under output.
        NativeConsole.PreferUtf8();
        return CliApp.Run(args);
    }

    private static int LaunchGui(string? initialPath, string? initialProfile, bool isGuiHost)
    {
        // Started from cmd/PowerShell: re-spawn detached so the shell prompt returns now,
        // instead of blocking until the WinForms window is closed.
        if (!isGuiHost && NativeConsole.SharesConsoleWithParent())
        {
            if (!TrySpawnDetachedGui(initialPath, initialProfile))
            {
                // Fall back to in-process GUI (shell will wait until the window closes).
                NativeConsole.Detach();
                return RunWinForms(initialPath, initialProfile);
            }
            return 0;
        }

        NativeConsole.Detach();
        return RunWinForms(initialPath, initialProfile);
    }

    private static int RunWinForms(string? initialPath, string? initialProfile)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.Run(new MainForm(initialPath, initialProfile));
        return 0;
    }

    private static bool TrySpawnDetachedGui(string? initialPath, string? initialProfile)
    {
        string? exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
            return false;

        var args = new StringBuilder();
        args.Append('/').Append(GuiHostSwitch);
        args.Append(" /gui");
        if (!string.IsNullOrWhiteSpace(initialPath))
        {
            args.Append(" /Target ");
            args.Append(QuoteArg(initialPath));
        }
        if (!string.IsNullOrWhiteSpace(initialProfile))
        {
            args.Append(" /Profile ");
            args.Append(QuoteArg(initialProfile));
        }

        try
        {
            using var _ = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args.ToString(),
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string QuoteArg(string value) =>
        value.Contains(' ', StringComparison.Ordinal) || value.Contains('"', StringComparison.Ordinal)
            ? "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\""
            : value;

    /// <summary>
    /// GUI when: no args, only <c>/gui</c>, or <c>/gui</c> plus optional path/profile.
    /// Everything else (including <c>/?</c> and <c>/Target</c> without <c>/gui</c>) is CLI.
    /// </summary>
    internal static bool ShouldLaunchGui(
        string[] args,
        out string? initialPath,
        out string? initialProfile,
        out bool isGuiHost)
    {
        initialPath = null;
        initialProfile = null;
        isGuiHost = false;

        if (args.Length == 0)
            return true;

        bool wantsGui = false;
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string key = a.TrimStart('-', '/');
            if (key.Equals(GuiHostSwitch, StringComparison.OrdinalIgnoreCase))
            {
                isGuiHost = true;
                wantsGui = true;
                continue;
            }
            if (key.Equals("gui", StringComparison.OrdinalIgnoreCase))
            {
                wantsGui = true;
                continue;
            }

            // Allow prefilling the GUI from /Target and /Profile when /gui is also present.
            if (key.Equals("target", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("t", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length) initialPath = args[++i];
                continue;
            }
            if (key.Equals("profile", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length) initialProfile = args[++i];
                continue;
            }

            // Any other switch/arg → CLI unless we already decided /gui-only workflow.
            if (a.StartsWith('-') || a.StartsWith('/'))
            {
                if (!wantsGui)
                    return false;
                continue;
            }

            // Positional path with /gui
            if (wantsGui && initialPath is null)
            {
                initialPath = a;
                continue;
            }

            if (!wantsGui)
                return false;
        }

        return wantsGui || args.Length == 0;
    }
}
