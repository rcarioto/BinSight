using System.Text;
using BinSight.Core.Analysis;
using BinSight.Core.Checks;
using BinSight.Core.Formats;
using BinSight.Core.Rules;
using Xunit;

namespace BinSight.Tests;

public class ElfMachOAndRulesTests
{
    [Fact]
    public void Detects_Elf_Magic()
    {
        string path = WriteTemp(new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 1, 1, 1 });
        try
        {
            Assert.Equal(BinaryFormat.Elf, BinaryFormatDetector.Detect(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Detects_MachO_Magic()
    {
        var buf = new byte[32];
        BitConverter.GetBytes(0xFEEDFACFu).CopyTo(buf, 0);
        string path = WriteTemp(buf);
        try
        {
            Assert.Equal(BinaryFormat.MachO, BinaryFormatDetector.Detect(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void CustomRules_BanImport_FailsWhenPresent()
    {
        // Use a tiny synthetic PE with KERNEL32!VirtualProtect via ChecksTests infrastructure if available;
        // otherwise validate rule JSON loading + EvaluateFile string rule.
        string rules = Path.GetTempFileName();
        string target = Path.GetTempFileName();
        try
        {
            File.WriteAllText(rules, """
                {"rules":[{"id":"x","match":"string","pattern":"SECRET_MARKER","expect":"absent","severity":"fail"}]}
                """);
            File.WriteAllBytes(target, Encoding.ASCII.GetBytes("hello SECRET_MARKER world"));
            var set = CustomRuleSet.Load(rules);
            var results = set.EvaluateFile(target);
            Assert.Contains(results, r => r.Status == CheckStatus.Fail);
        }
        finally
        {
            File.Delete(rules);
            File.Delete(target);
        }
    }

    [Fact]
    public void BinaryScanner_Rejects_Unknown()
    {
        string path = WriteTemp(Encoding.ASCII.GetBytes("NOT_A_BINARY"));
        try
        {
            var scanner = new BinaryScanner(CheckRegistry.Defaults);
            var report = scanner.Analyze(path);
            Assert.True(report.ErrorCount >= 1 || report.Results.Any(r => r.Status == CheckStatus.Error));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void SimpleYaraParser_Extracts_Strings()
    {
        var rules = SimpleYaraParser.Parse("""
            rule Demo
            {
                strings:
                    $a = "password="
                condition:
                    $a
            }
            """);
        Assert.Single(rules);
        Assert.Equal("Demo", rules[0].Name);
        Assert.Equal("password=", Encoding.UTF8.GetString(rules[0].Strings[0]));
    }

    private static string WriteTemp(byte[] data)
    {
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
    }
}
