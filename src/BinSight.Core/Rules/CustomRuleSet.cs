using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using BinSight.Core.Checks;
using BinSight.Core.Formats;
using BinSight.Core.PE;

namespace BinSight.Core.Rules;

/// <summary>JSON custom policy rules for banned imports, sections, and byte/string patterns.</summary>
public sealed class CustomRuleSet
{
    [JsonPropertyName("rules")]
    public List<CustomRule> Rules { get; set; } = new();

    public static CustomRuleSet Load(string path)
    {
        string json = File.ReadAllText(path);
        var set = JsonSerializer.Deserialize<CustomRuleSet>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        }) ?? new CustomRuleSet();
        return set;
    }

    public IReadOnlyList<CheckResult> EvaluatePe(PEFile pe)
    {
        var results = new List<CheckResult>();
        foreach (var rule in Rules)
        {
            var hit = rule.Match switch
            {
                "import" => MatchImport(pe, rule),
                "section" => MatchSection(pe, rule),
                "bytes" or "string" => MatchBytes(pe.FilePath, rule),
                _ => (matched: false, detail: $"Unknown match type '{rule.Match}'."),
            };
            results.Add(ToResult(rule, hit.matched, hit.detail));
        }
        return results;
    }

    public IReadOnlyList<CheckResult> EvaluateFile(string path)
    {
        var results = new List<CheckResult>();
        foreach (var rule in Rules.Where(r => r.Match is "bytes" or "string"))
        {
            var hit = MatchBytes(path, rule);
            results.Add(ToResult(rule, hit.matched, hit.detail));
        }
        return results;
    }

    private static (bool matched, string detail) MatchImport(PEFile pe, CustomRule rule)
    {
        foreach (var imp in pe.ReadImports())
        {
            if (!string.IsNullOrWhiteSpace(rule.Dll) &&
                !imp.DllName.Equals(rule.Dll, StringComparison.OrdinalIgnoreCase) &&
                !imp.DllName.StartsWith(rule.Dll.TrimEnd('*'), StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var sym in imp.Symbols)
            {
                if (sym.Name is null) continue;
                if (NameMatches(sym.Name, rule.Function))
                    return (true, $"{imp.DllName}!{sym.Name}");
            }
        }
        return (false, "No matching import.");
    }

    private static (bool matched, string detail) MatchSection(PEFile pe, CustomRule rule)
    {
        foreach (var s in pe.Sections)
        {
            if (NameMatches(s.Name, rule.Name ?? rule.Section))
                return (true, $"Section {s.Name} chars=0x{s.Characteristics:X}");
        }
        return (false, "No matching section.");
    }

    private static (bool matched, string detail) MatchBytes(string path, CustomRule rule)
    {
        byte[] data = File.ReadAllBytes(path);
        if (!string.IsNullOrEmpty(rule.Pattern))
        {
            byte[] needle = EncodingPattern(rule.Pattern);
            int idx = IndexOf(data, needle);
            return idx >= 0
                ? (true, $"Pattern hit at file offset 0x{idx:X}")
                : (false, "Pattern not found.");
        }
        if (!string.IsNullOrEmpty(rule.Regex))
        {
            // Scan as Latin-1 text for regex convenience.
            string text = System.Text.Encoding.Latin1.GetString(data);
            var m = Regex.Match(text, rule.Regex, RegexOptions.Multiline);
            return m.Success
                ? (true, $"Regex hit at index {m.Index}")
                : (false, "Regex not found.");
        }
        return (false, "Rule has no pattern/regex.");
    }

    private static CheckResult ToResult(CustomRule rule, bool matched, string detail)
    {
        string id = string.IsNullOrWhiteSpace(rule.Id) ? "CustomRule" : rule.Id;
        string checkName = "CustomRulesCheck";
        bool failOnMatch = !string.Equals(rule.Severity, "pass", StringComparison.OrdinalIgnoreCase)
                           && !string.Equals(rule.Severity, "info", StringComparison.OrdinalIgnoreCase);

        // expect=absent (default): violation if the pattern/import is found (banned item).
        // expect=present: violation if missing (required item).
        bool wantAbsence = !string.Equals(rule.Expect, "present", StringComparison.OrdinalIgnoreCase);
        bool violation = wantAbsence ? matched : !matched;

        string msg = rule.Message ?? (violation
            ? $"Custom rule '{id}' triggered ({detail})."
            : $"Custom rule '{id}' satisfied ({detail}).");

        if (!violation)
            return CheckResult.Pass(checkName, msg, new[] { $"rule={id}", detail });

        if (string.Equals(rule.Severity, "warn", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rule.Severity, "warning", StringComparison.OrdinalIgnoreCase))
            return CheckResult.Pass(checkName, "WARN: " + msg, new[] { $"rule={id}", detail });

        return failOnMatch
            ? CheckResult.Fail(checkName, msg, new[] { $"rule={id}", detail })
            : CheckResult.Pass(checkName, msg, new[] { $"rule={id}", detail });
    }

    private static bool NameMatches(string value, string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern) || pattern == "*") return true;
        if (pattern.EndsWith('*'))
            return value.StartsWith(pattern.TrimEnd('*'), StringComparison.OrdinalIgnoreCase);
        return value.Equals(pattern, StringComparison.OrdinalIgnoreCase);
    }

    private static byte[] EncodingPattern(string pattern)
    {
        // Support hex form: hex:48656c6c6f or plain UTF-8 text.
        if (pattern.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
        {
            string hex = pattern[4..].Replace(" ", "", StringComparison.Ordinal);
            var buf = new byte[hex.Length / 2];
            for (int i = 0; i < buf.Length; i++)
                buf[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return buf;
        }
        return System.Text.Encoding.UTF8.GetBytes(pattern);
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        for (int i = 0; i <= hay.Length - needle.Length; i++)
        {
            int j = 0;
            for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
            if (j == needle.Length) return i;
        }
        return -1;
    }
}

public sealed class CustomRule
{
    public string? Id { get; set; }
    public string Match { get; set; } = "import"; // import | section | bytes | string
    public string? Dll { get; set; }
    public string? Function { get; set; }
    public string? Name { get; set; }
    public string? Section { get; set; }
    public string? Pattern { get; set; }
    public string? Regex { get; set; }
    public string Severity { get; set; } = "fail"; // fail | warn | pass | info
    public string Expect { get; set; } = "absent"; // absent = fail if found; present = fail if missing
    public string? Message { get; set; }
}
