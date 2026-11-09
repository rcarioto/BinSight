using BinSight.Core.Analysis;
using BinSight.Core.Checks;
using BinSight.Core.PE;
using BinSight.Core.Symbols;
using Xunit;

namespace BinSight.Tests;

public class ModernAndSymbolsTests
{
    [Fact]
    public void TargetEnumerator_FindsDllsInDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), "binsight_enum_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string pe = Path.Combine(dir, "a.dll");
            File.WriteAllBytes(pe, SyntheticPE.NewHealthyPE32Plus().Build());
            File.WriteAllText(Path.Combine(dir, "notes.txt"), "ignore me");

            var found = TargetEnumerator.Expand(dir, recurse: false);
            Assert.Single(found);
            Assert.EndsWith("a.dll", found[0], StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void BinaryEra_ClassifiesModernLinker()
    {
        var pe = PEFile.Parse("t.dll", SyntheticPE.NewHealthyPE32Plus().Build());
        var era = BinaryEra.Classify(pe);
        Assert.Contains("Modern", era.Label, StringComparison.OrdinalIgnoreCase);
        Assert.False(era.IsLegacyTooling);
    }

    [Fact]
    public void BinaryEra_ClassifiesLegacyLinker()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.MajorLinkerVersion = 7;
        synth.MinorLinkerVersion = 10;
        var pe = PEFile.Parse("old.dll", synth.Build());
        var era = BinaryEra.Classify(pe);
        Assert.True(era.IsLegacyTooling);
    }

    [Fact]
    public void SymbolResolver_NoCodeView_IsNoneReferenced()
    {
        var pe = PEFile.Parse("t.dll", SyntheticPE.NewHealthyPE32Plus().Build());
        var status = SymbolResolver.Resolve(pe, null);
        Assert.Equal(SymbolAvailability.NoneReferenced, status.Availability);
        Assert.NotEmpty(status.AdvisoryNotes);
    }

    [Fact]
    public void CETCheck_FailsWithoutExtendedCharacteristics()
    {
        var pe = PEFile.Parse("t.dll", SyntheticPE.NewHealthyPE32Plus().Build());
        Assert.Equal(CheckStatus.Fail, new CETCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void CETCheck_NotApplicableOnX86()
    {
        var pe = PEFile.Parse("t.dll", SyntheticPE.NewHealthyPE32().Build());
        Assert.Equal(CheckStatus.NotApplicable, new CETCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void RegistryIncludesModernChecks()
    {
        Assert.NotNull(CheckRegistry.Find("CFGCheck"));
        Assert.NotNull(CheckRegistry.Find("CETCheck"));
        Assert.NotNull(CheckRegistry.Find("RelocsStrippedCheck"));
        Assert.NotNull(CheckRegistry.Find("AuthenticodeCheck"));
        Assert.NotNull(CheckRegistry.Find("DelayLoadCheck"));
        Assert.NotNull(CheckRegistry.Find("ManifestUACCheck"));
        Assert.NotNull(CheckRegistry.Find("SymbolsCheck"));
        Assert.False(CheckRegistry.Find("AuthenticodeCheck")!.EnabledByDefault);
        Assert.True(CheckRegistry.Find("CFGCheck")!.EnabledByDefault);
    }
}
