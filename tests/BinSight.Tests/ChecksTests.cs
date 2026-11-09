using BinSight.Core.Checks;
using BinSight.Core.PE;
using Xunit;

namespace BinSight.Tests;

public class ChecksTests
{
    private static PEFile BuildAndLoad(SyntheticPE synth) => PEFile.Parse("test.bin", synth.Build());

    [Fact]
    public void DBCheck_FailsWhenAslrMissing()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.DllCharacteristics = (ushort)(synth.DllCharacteristics & ~PEConstants.DllCharDynamicBase);
        var pe = BuildAndLoad(synth);
        var r = new DBCheck().Run(pe, new CheckContext());
        Assert.Equal(CheckStatus.Fail, r.Status);
    }

    [Fact]
    public void DBCheck_PassesWhenAslrPresent()
    {
        var pe = BuildAndLoad(SyntheticPE.NewHealthyPE32());
        var r = new DBCheck().Run(pe, new CheckContext());
        Assert.Equal(CheckStatus.Pass, r.Status);
    }

    [Fact]
    public void NXCheck_FailsWhenNxMissing()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.DllCharacteristics = (ushort)(synth.DllCharacteristics & ~PEConstants.DllCharNxCompat);
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new NXCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void HighEntropyVACheck_NotApplicableOnPE32()
    {
        var pe = BuildAndLoad(SyntheticPE.NewHealthyPE32());
        var r = new HighEntropyVACheck().Run(pe, new CheckContext());
        Assert.Equal(CheckStatus.NotApplicable, r.Status);
    }

    [Fact]
    public void HighEntropyVACheck_RequiresBothFlagsOn64Bit()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        synth.DllCharacteristics = (ushort)(synth.DllCharacteristics & ~PEConstants.DllCharHighEntropyVa);
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new HighEntropyVACheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void WXCheck_FailsOnWritableExecutableSection()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.Sections.Add(new SyntheticSection(".wx",
            PEConstants.SectionMemRead | PEConstants.SectionMemWrite | PEConstants.SectionMemExecute));
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new WXCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void SharedSectionCheck_FailsOnWritableShared()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.Sections.Add(new SyntheticSection(".ss",
            PEConstants.SectionMemRead | PEConstants.SectionMemWrite | PEConstants.SectionMemShared));
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new SharedSectionCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void SafeSEHCheck_NotApplicableFor64Bit()
    {
        var pe = BuildAndLoad(SyntheticPE.NewHealthyPE32Plus());
        Assert.Equal(CheckStatus.NotApplicable, new SafeSEHCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void SafeSEHCheck_PassesWhenNoSehFlagSet()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.DllCharacteristics |= PEConstants.DllCharNoSeh;
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Pass, new SafeSEHCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void GSCheck_FailsWithoutLoadConfig()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        synth.LoadConfig = null;
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new GSCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void GSCheck_PassesWithSecurityCookie()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        synth.LoadConfig = new SyntheticLoadConfig { HasSecurityCookie = true };
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Pass, new GSCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void ExecutableImportsCheck_PassesWhenIatInNonExecSection()
    {
        var pe = BuildAndLoad(SyntheticPE.NewHealthyPE32Plus());
        Assert.Equal(CheckStatus.Pass, new ExecutableImportsCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void VB6Check_PassesForNonVbBinary()
    {
        var pe = BuildAndLoad(SyntheticPE.NewHealthyPE32Plus());
        Assert.Equal(CheckStatus.Pass, new VB6Check().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void VB6Check_FailsWhenMsvbvmImported()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.Imports.Add(new SyntheticImport("MSVBVM60.DLL", new[] { "#100" }));
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new VB6Check().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void RSA32Check_FailsWhenRsa32Imported()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.Imports.Add(new SyntheticImport("RSA32.DLL", new[] { "RSAEncrypt" }));
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new RSA32Check().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void GSFriendlyInitCheck_PassesWithQpcImported()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        synth.LoadConfig = new SyntheticLoadConfig { HasSecurityCookie = true };
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Pass, new GSFriendlyInitCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void FunctionPointersCheck_FailsWithoutCfg()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.DllCharacteristics = (ushort)(synth.DllCharacteristics & ~PEConstants.DllCharGuardCf);
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new FunctionPointersCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void CompilerVersionCheck_FailsForOldLinker()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.MajorLinkerVersion = 8;
        synth.MinorLinkerVersion = 0;
        var pe = BuildAndLoad(synth);
        var r = new CompilerVersionCheck().Run(pe, new CheckContext());
        Assert.Equal(CheckStatus.Fail, r.Status);
    }

    [Fact]
    public void AnalyzerRunsFullDefaultSet()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        synth.LoadConfig = new SyntheticLoadConfig
        {
            HasSecurityCookie = true,
            GuardCfCheckFunction = 0x1000,
            GuardFlags = PEConstants.GuardCfInstrumented,
        };
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, synth.Build());
            var report = BinSight.Core.Analysis.Analyzer.Default().Analyze(path);
            Assert.NotEmpty(report.Results);
            // No check should throw / return Error.
            Assert.Equal(0, report.ErrorCount);
            Assert.NotNull(report.Symbols);
            Assert.NotNull(report.Era);
            Assert.Contains(report.Results, r => r.CheckName == "CFGCheck");
            Assert.Contains(report.Results, r => r.CheckName == "SymbolsCheck");
            Assert.Contains(report.Results, r => r.CheckName == "CETCheck");
            Assert.Equal(CheckStatus.Pass, report.Results.First(r => r.CheckName == "CFGCheck").Status);
            Assert.Equal(CheckStatus.Pass, report.Results.First(r => r.CheckName == "SymbolsCheck").Status);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RelocsStrippedCheck_FailsWhenFlagSet()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        synth.FileCharacteristics |= PEConstants.FileRelocsStripped;
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Fail, new RelocsStrippedCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void CFGCheck_PassesWhenConfigured()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        synth.LoadConfig = new SyntheticLoadConfig
        {
            HasSecurityCookie = true,
            GuardCfCheckFunction = 0x1000,
            GuardFlags = PEConstants.GuardCfInstrumented,
        };
        var pe = BuildAndLoad(synth);
        Assert.Equal(CheckStatus.Pass, new CFGCheck().Run(pe, new CheckContext()).Status);
    }

    [Fact]
    public void SymbolsCheck_PassesWithoutPdb()
    {
        var pe = BuildAndLoad(SyntheticPE.NewHealthyPE32Plus());
        var r = new SymbolsCheck().Run(pe, new CheckContext());
        Assert.Equal(CheckStatus.Pass, r.Status);
        Assert.Contains("without", r.Message, StringComparison.OrdinalIgnoreCase);
    }
}
