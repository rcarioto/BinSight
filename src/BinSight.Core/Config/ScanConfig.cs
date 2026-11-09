using System.Xml.Linq;
using BinSight.Core.Checks;

namespace BinSight.Core.Config;

/// <summary>Loaded team policy from a BinSightConfig XML file.</summary>
public sealed class ScanConfig
{
    public List<string> Checks { get; } = new();
    public List<string> SkippedChecks { get; } = new();
    public List<string> FailOn { get; } = new();
    public string? Profile { get; set; }
    public string? SymbolSearchPath { get; set; }
    public int? MinimumLinkerMajor { get; set; }
    public int? MinimumLinkerMinor { get; set; }
    public int? MinimumCompilerMajor { get; set; }
    public int? MinimumCompilerMinor { get; set; }

    public static ScanConfig Load(string path)
    {
        var doc = XDocument.Load(path);
        var root = doc.Root ?? throw new InvalidDataException("Config root missing.");
        var cfg = new ScanConfig();

        foreach (var el in root.Element("Checks")?.Elements("Check") ?? Enumerable.Empty<XElement>())
        {
            var name = (string?)el.Attribute("name") ?? el.Value;
            if (!string.IsNullOrWhiteSpace(name)) cfg.Checks.Add(name.Trim());
        }
        foreach (var el in root.Element("SkippedChecks")?.Elements("Check") ?? Enumerable.Empty<XElement>())
        {
            var name = (string?)el.Attribute("name") ?? el.Value;
            if (!string.IsNullOrWhiteSpace(name)) cfg.SkippedChecks.Add(name.Trim());
        }
        foreach (var el in root.Element("FailOn")?.Elements("Check") ?? Enumerable.Empty<XElement>())
        {
            var name = (string?)el.Attribute("name") ?? el.Value;
            if (!string.IsNullOrWhiteSpace(name)) cfg.FailOn.Add(name.Trim());
        }

        cfg.Profile = root.Element("Profile")?.Value?.Trim();
        cfg.SymbolSearchPath = root.Element("SymPath")?.Value?.Trim();

        ParseVersion(root.Element("MinimumLinkerVersion")?.Value, out var lMaj, out var lMin);
        cfg.MinimumLinkerMajor = lMaj; cfg.MinimumLinkerMinor = lMin;
        ParseVersion(root.Element("MinimumCompilerVersion")?.Value, out var cMaj, out var cMin);
        cfg.MinimumCompilerMajor = cMaj; cfg.MinimumCompilerMinor = cMin;

        return cfg;
    }

    /// <summary>Resolve the effective check list from config + optional CLI overrides.</summary>
    public IReadOnlyList<ICheck> ResolveChecks(string? cliProfile, IEnumerable<string> cliChecks, IEnumerable<string> cliSkipped, out string? error)
    {
        error = null;
        var checks = cliChecks.ToList();
        var skipped = cliSkipped.Concat(SkippedChecks).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        IEnumerable<ICheck> baseSet;
        if (checks.Count > 0 || this.Checks.Count > 0)
        {
            var names = checks.Count > 0 ? checks : this.Checks;
            var resolved = new List<ICheck>();
            foreach (var name in names)
            {
                var c = CheckRegistry.Find(name);
                if (c is null)
                {
                    error = $"Unknown check in config/CLI: {name}";
                    return Array.Empty<ICheck>();
                }
                if (!resolved.Any(r => r.Name.Equals(c.Name, StringComparison.OrdinalIgnoreCase)))
                    resolved.Add(c);
            }
            baseSet = resolved;
        }
        else
        {
            string? profile = cliProfile ?? Profile;
            baseSet = ResolveProfile(profile, out error);
            if (error is not null) return Array.Empty<ICheck>();
        }

        if (skipped.Count > 0)
        {
            var skip = new HashSet<string>(skipped, StringComparer.OrdinalIgnoreCase);
            baseSet = baseSet.Where(c => !skip.Contains(c.Name));
        }
        return baseSet.ToList();
    }

    private static IEnumerable<ICheck> ResolveProfile(string? profile, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(profile) ||
            profile.Equals("default", StringComparison.OrdinalIgnoreCase) ||
            profile.Equals("modern", StringComparison.OrdinalIgnoreCase))
            return CheckRegistry.Defaults;

        if (profile.Equals("binscope2014", StringComparison.OrdinalIgnoreCase) ||
            profile.Equals("binscope", StringComparison.OrdinalIgnoreCase))
        {
            return CheckRegistry.BinScope2014
                .Where(c => c.EnabledByDefault)
                .Append(new SymbolsCheck())
                .Append(new GSSymbolsCheck());
        }

        if (profile.Equals("audit", StringComparison.OrdinalIgnoreCase))
            return CheckRegistry.All;

        error = $"Unknown profile '{profile}'.";
        return Array.Empty<ICheck>();
    }

    private static void ParseVersion(string? value, out int? major, out int? minor)
    {
        major = null; minor = null;
        if (string.IsNullOrWhiteSpace(value)) return;
        var parts = value.Split('.', 2);
        if (int.TryParse(parts[0], out var maj)) major = maj;
        if (parts.Length == 2 && int.TryParse(parts[1], out var min)) minor = min;
    }
}
