using BinSight.Core.PE;
using Xunit;

namespace BinSight.Tests;

public class PEParsingTests
{
    [Fact]
    public void ParsesPE32Headers()
    {
        var synth = SyntheticPE.NewHealthyPE32();
        var pe = PEFile.Parse("test.exe", synth.Build());
        Assert.False(pe.Headers.Is64Bit);
        Assert.True(pe.Headers.Is32Bit);
        Assert.Equal("x86", pe.Headers.MachineName);
        Assert.True(pe.Sections.Count >= 3);
    }

    [Fact]
    public void ParsesPE32PlusHeaders()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        var pe = PEFile.Parse("test.dll", synth.Build());
        Assert.True(pe.Headers.Is64Bit);
        Assert.Equal("x64", pe.Headers.MachineName);
    }

    [Fact]
    public void ParsesImportDirectory()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        var pe = PEFile.Parse("test.dll", synth.Build());
        var imports = pe.ReadImports();
        Assert.Single(imports);
        Assert.Equal("KERNEL32.dll", imports[0].DllName);
        Assert.Contains(imports[0].Symbols, s => s.Name == "QueryPerformanceCounter");
    }

    [Fact]
    public void RejectsNonPEBuffer()
    {
        var bad = new byte[128];
        Assert.Throws<InvalidPEException>(() => PEFile.Parse("junk", bad));
    }
}
