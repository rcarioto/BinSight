using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using BinSight.Core.PE;
using BinSight.Core.Rules;

namespace BinSight.Core.Checks;

/// <summary>Applies JSON custom rules from <c>/Rules</c>.</summary>
public sealed class CustomRulesCheck : ICheck
{
    public string Name => "CustomRulesCheck";
    public string Description => "Evaluates organization JSON rules (/Rules) for banned imports, sections, and patterns.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (string.IsNullOrWhiteSpace(ctx.CustomRulesPath))
            return CheckResult.NotApplicable(Name, "No /Rules file provided.");

        if (!File.Exists(ctx.CustomRulesPath))
            return CheckResult.Error(Name, $"Rules file not found: {ctx.CustomRulesPath}");

        try
        {
            var set = CustomRuleSet.Load(ctx.CustomRulesPath);
            if (set.Rules.Count == 0)
                return CheckResult.Pass(Name, "Rules file loaded but contains no rules.");

            var results = set.EvaluatePe(pe);
            var fails = results.Where(r => r.Status == CheckStatus.Fail).ToList();
            var details = results.SelectMany(r => new[] { $"[{r.Status}] {r.Message}" }
                .Concat(r.Details ?? Array.Empty<string>())).ToList();

            if (fails.Count > 0)
                return CheckResult.Fail(Name, $"{fails.Count}/{results.Count} custom rule(s) failed.", details);

            return CheckResult.Pass(Name, $"All {results.Count} custom rule(s) satisfied.", details);
        }
        catch (Exception ex)
        {
            return CheckResult.Error(Name, $"Failed to evaluate rules: {ex.Message}");
        }
    }
}

/// <summary>
/// YARA-style hooks: runs the <c>yara</c> CLI when installed, otherwise evaluates a simple
/// strings-only subset of .yar files (rule Name { strings: $a = "..." condition: $a }).
/// </summary>
public sealed class YaraRulesCheck : ICheck
{
    public string Name => "YaraRulesCheck";
    public string Description => "Runs YARA rules (/Yara) via the yara CLI when available, or a built-in strings-only subset.";
    public bool EnabledByDefault => true;

    public CheckResult Run(PEFile pe, CheckContext ctx)
    {
        if (string.IsNullOrWhiteSpace(ctx.YaraRulesPath))
            return CheckResult.NotApplicable(Name, "No /Yara rules path provided.");

        if (!File.Exists(ctx.YaraRulesPath) && !Directory.Exists(ctx.YaraRulesPath))
            return CheckResult.Error(Name, $"YARA rules path not found: {ctx.YaraRulesPath}");

        if (TryRunYaraCli(ctx.YaraRulesPath, pe.FilePath, out var cliResult))
            return cliResult;

        // Fallback: strings-only subset.
        try
        {
            var files = EnumerateRuleFiles(ctx.YaraRulesPath).ToList();
            if (files.Count == 0)
                return CheckResult.Error(Name, "No .yar/.yara files found.");

            byte[] data = File.ReadAllBytes(pe.FilePath);
            var hits = new List<string>();
            foreach (var file in files)
            {
                foreach (var rule in SimpleYaraParser.Parse(File.ReadAllText(file)))
                {
                    if (rule.Strings.Any(s => Contains(data, s)))
                        hits.Add($"{rule.Name} ({Path.GetFileName(file)})");
                }
            }

            if (hits.Count > 0)
                return CheckResult.Fail(Name,
                    $"YARA-style string rules matched: {hits.Count}.",
                    hits);

            return CheckResult.Pass(Name,
                $"No matches across {files.Count} YARA-style rule file(s) (built-in strings subset; install `yara` for full engine).");
        }
        catch (Exception ex)
        {
            return CheckResult.Error(Name, $"YARA-style evaluation failed: {ex.Message}");
        }
    }

    private static bool TryRunYaraCli(string rulesPath, string target, out CheckResult result)
    {
        result = CheckResult.Pass("YaraRulesCheck", "");
        string? exe = FindOnPath("yara") ?? FindOnPath("yara64") ?? FindOnPath("yara32");
        if (exe is null) return false;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = $"-r \"{rulesPath}\" \"{target}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return false;
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(60_000);

            var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            if (proc.ExitCode == 0 && lines.Count == 0)
            {
                result = CheckResult.Pass("YaraRulesCheck", $"yara CLI reported no matches ({exe}).");
                return true;
            }

            if (lines.Count > 0)
            {
                result = CheckResult.Fail("YaraRulesCheck",
                    $"yara CLI matched {lines.Count} rule(s).",
                    lines.Take(50).ToList());
                return true;
            }

            result = CheckResult.Error("YaraRulesCheck",
                $"yara exited {proc.ExitCode}: {Truncate(stderr, 300)}");
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<string> EnumerateRuleFiles(string path)
    {
        if (File.Exists(path)) { yield return path; yield break; }
        foreach (var f in Directory.EnumerateFiles(path, "*.yar", SearchOption.AllDirectories)
                     .Concat(Directory.EnumerateFiles(path, "*.yara", SearchOption.AllDirectories)))
            yield return f;
    }

    private static string? FindOnPath(string name)
    {
        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (pathEnv is null) return null;
        foreach (var dir in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate = Path.Combine(dir, name);
            if (File.Exists(candidate)) return candidate;
            if (OperatingSystem.IsWindows())
            {
                string exe = candidate + ".exe";
                if (File.Exists(exe)) return exe;
            }
        }
        return null;
    }

    private static bool Contains(byte[] hay, byte[] needle)
    {
        for (int i = 0; i <= hay.Length - needle.Length; i++)
        {
            int j = 0;
            for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
            if (j == needle.Length) return true;
        }
        return false;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}

public static class SimpleYaraParser
{
    public sealed record SimpleRule(string Name, IReadOnlyList<byte[]> Strings);

    public static IReadOnlyList<SimpleRule> Parse(string text)
    {
        var rules = new List<SimpleRule>();
        // Very small subset: rule Name { strings: $a = "text" ... condition: any of them }
        var ruleMatches = Regex.Matches(text, @"rule\s+(\w+)\s*\{(?<body>.*?)\n\}",
            RegexOptions.Singleline | RegexOptions.IgnoreCase);
        foreach (Match rm in ruleMatches)
        {
            string name = rm.Groups[1].Value;
            string body = rm.Groups["body"].Value;
            var strings = new List<byte[]>();
            foreach (Match sm in Regex.Matches(body, @"=\s*""((?:\\.|[^""])*)"""))
            {
                string raw = Regex.Unescape(sm.Groups[1].Value);
                strings.Add(Encoding.UTF8.GetBytes(raw));
            }
            foreach (Match sm in Regex.Matches(body, @"=\s*\{([0-9A-Fa-f\s]+)\}"))
            {
                string hex = Regex.Replace(sm.Groups[1].Value, @"\s+", "");
                if (hex.Length % 2 != 0) continue;
                var buf = new byte[hex.Length / 2];
                for (int i = 0; i < buf.Length; i++)
                    buf[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                strings.Add(buf);
            }
            if (strings.Count > 0)
                rules.Add(new SimpleRule(name, strings));
        }
        return rules;
    }
}
