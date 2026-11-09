using Xunit;

namespace BinSight.Tests;

/// <summary>
/// Mirrors Program.ShouldLaunchGui logic via a small copy so Core tests don't reference WinForms.
/// Kept in sync with src/BinSight/Program.cs.
/// </summary>
public class EntryPointModeTests
{
    private const string GuiHostSwitch = "internal-gui-host";

    [Theory]
    [InlineData(new string[0], true)]
    [InlineData(new[] { "/gui" }, true)]
    [InlineData(new[] { "/gui", "/Target", "C:\\a.exe" }, true)]
    [InlineData(new[] { "/internal-gui-host", "/gui" }, true)]
    [InlineData(new[] { "/Target", "C:\\a.exe" }, false)]
    [InlineData(new[] { "/ListChecks" }, false)]
    [InlineData(new[] { "/?", }, false)]
    [InlineData(new[] { "C:\\a.exe" }, false)]
    public void GuiVsCliDispatch(string[] args, bool expectGui)
    {
        Assert.Equal(expectGui, ShouldLaunchGui(args, out _, out _, out _));
    }

    [Fact]
    public void GuiPrefillsTargetAndProfile()
    {
        Assert.True(ShouldLaunchGui(new[] { "/gui", "/Target", @"C:\x.exe", "/Profile", "audit" }, out var path, out var profile, out var host));
        Assert.Equal(@"C:\x.exe", path);
        Assert.Equal("audit", profile);
        Assert.False(host);
    }

    [Fact]
    public void InternalGuiHostIsDetected()
    {
        Assert.True(ShouldLaunchGui(new[] { "/" + GuiHostSwitch, "/gui", "/Target", @"C:\x.exe" }, out var path, out _, out var host));
        Assert.True(host);
        Assert.Equal(@"C:\x.exe", path);
    }

    // --- keep aligned with BinSight.Program.ShouldLaunchGui ---
    private static bool ShouldLaunchGui(string[] args, out string? initialPath, out string? initialProfile, out bool isGuiHost)
    {
        initialPath = null;
        initialProfile = null;
        isGuiHost = false;
        if (args.Length == 0) return true;

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
            if (a.StartsWith('-') || a.StartsWith('/'))
            {
                if (!wantsGui) return false;
                continue;
            }
            if (wantsGui && initialPath is null)
            {
                initialPath = a;
                continue;
            }
            if (!wantsGui) return false;
        }
        return wantsGui;
    }
}
