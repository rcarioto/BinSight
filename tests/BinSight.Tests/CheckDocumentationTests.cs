using BinSight.Core.Checks;
using Xunit;

namespace BinSight.Tests;

public class CheckDocumentationTests
{
    [Fact]
    public void EveryRegisteredCheckHasSecurityDocumentation()
    {
        foreach (var check in CheckRegistry.All)
        {
            var guide = CheckDocumentation.TryGet(check.Name);
            Assert.True(guide is not null, $"Missing CheckDocumentation entry for {check.Name}");
            Assert.False(string.IsNullOrWhiteSpace(guide!.Purpose));
            Assert.False(string.IsNullOrWhiteSpace(guide.WhyItMatters));
            Assert.False(string.IsNullOrWhiteSpace(guide.RoleInBinary));
            Assert.False(string.IsNullOrWhiteSpace(guide.IfPasses));
            Assert.False(string.IsNullOrWhiteSpace(guide.IfFails));
            Assert.False(string.IsNullOrWhiteSpace(guide.WhenFailMayBeExpected));
            Assert.False(string.IsNullOrWhiteSpace(guide.RealIssueSignal));
            Assert.NotNull(guide.AskTheTeam);
            Assert.NotEmpty(guide.AskTheTeam);
            Assert.All(guide.AskTheTeam, q => Assert.False(string.IsNullOrWhiteSpace(q)));
            Assert.NotEqual(guide.IfPasses, guide.IfFails);
            Assert.NotEqual(guide.WhenFailMayBeExpected, guide.RealIssueSignal);
        }
    }

    [Fact]
    public void CheckResult_AttachesGuideAndStatusMeaning()
    {
        var pass = CheckResult.Pass("DBCheck", "ok");
        Assert.NotNull(pass.Guide);
        Assert.Contains("ASLR", pass.SecurityMeaning!, StringComparison.OrdinalIgnoreCase);

        var fail = CheckResult.Fail("DBCheck", "missing");
        Assert.Contains("not enabled", fail.SecurityMeaning!, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(pass.SecurityMeaning, fail.SecurityMeaning);
        Assert.Contains("DYNAMICBASE", fail.Guide!.WhenFailMayBeExpected, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(fail.Guide.AskTheTeam);
    }

    [Fact]
    public void DefaultGSCookie_DocumentsStaticScanNoise()
    {
        var g = CheckDocumentation.TryGet("DefaultGSCookieCheck");
        Assert.NotNull(g);
        Assert.Contains("static", g!.WhenFailMayBeExpected, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("dump", g.RealIssueSignal, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(g.AskTheTeam, q => q.Contains("static", StringComparison.OrdinalIgnoreCase)
                                         || q.Contains("dump", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DangerousApi_DocumentsRuntimeHostNoise()
    {
        var g = CheckDocumentation.TryGet("DangerousApiCheck");
        Assert.NotNull(g);
        Assert.Contains("VirtualProtect", g!.WhenFailMayBeExpected, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(g.AskTheTeam, q => q.Contains("feature", StringComparison.OrdinalIgnoreCase)
                                         || q.Contains("host", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CetCheck_DocumentsApphostLimitation()
    {
        var g = CheckDocumentation.TryGet("CETCheck");
        Assert.NotNull(g);
        Assert.Contains("apphost", g!.WhenFailMayBeExpected, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(g.AskTheTeam, q => q.Contains("own the linker", StringComparison.OrdinalIgnoreCase)
                                         || q.Contains("linker command", StringComparison.OrdinalIgnoreCase));
    }
}
