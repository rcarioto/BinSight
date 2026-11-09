using System.Text.Json;
using BinSight.Core.Checks;

namespace BinSight.Core.Analysis;

/// <summary>Serializable snapshot of pass/fail per target+check for regression diffs.</summary>
public sealed class BaselineSnapshot
{
    public string CreatedUtc { get; set; } = DateTimeOffset.UtcNow.ToString("O");
    public string Root { get; set; } = "";
    public List<BaselineEntry> Entries { get; set; } = new();
}

public sealed class BaselineEntry
{
    public string Target { get; set; } = "";
    public string Check { get; set; } = "";
    public string Status { get; set; } = "";
}

public sealed record BaselineDiff(
    int NewFailures,
    int ResolvedFailures,
    int UnchangedFailures,
    IReadOnlyList<string> NewFailureLines,
    IReadOnlyList<string> ResolvedFailureLines);

/// <summary>Compare a current batch against a previously saved baseline JSON.</summary>
public static class BaselineComparer
{
    public static BaselineSnapshot Capture(BatchAnalysisReport batch)
    {
        var snap = new BaselineSnapshot { Root = batch.RootPath };
        foreach (var report in batch.Reports)
        {
            string rel = report.TargetPath;
            foreach (var r in report.Results)
            {
                snap.Entries.Add(new BaselineEntry
                {
                    Target = rel,
                    Check = r.CheckName,
                    Status = r.Status.ToString(),
                });
            }
        }
        return snap;
    }

    public static void Save(BaselineSnapshot snap, string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var json = JsonSerializer.Serialize(snap, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }

    public static BaselineSnapshot Load(string path)
    {
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<BaselineSnapshot>(json)
               ?? throw new InvalidDataException("Baseline file was empty or invalid.");
    }

    public static BaselineDiff Diff(BaselineSnapshot baseline, BatchAnalysisReport current)
    {
        static string Key(string t, string c) => t + "\0" + c;

        var baseFails = new HashSet<string>(
            baseline.Entries.Where(e => e.Status == nameof(CheckStatus.Fail))
                .Select(e => Key(Normalize(e.Target), e.Check)),
            StringComparer.OrdinalIgnoreCase);

        var curFails = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var report in current.Reports)
        {
            string t = Normalize(report.TargetPath);
            foreach (var r in report.Results.Where(r => r.Status == CheckStatus.Fail))
                curFails[Key(t, r.CheckName)] = $"{t} :: {r.CheckName}";
        }

        var neu = curFails.Keys.Where(k => !baseFails.Contains(k)).Select(k => curFails[k]).OrderBy(s => s).ToList();
        var resolved = baseFails.Where(k => !curFails.ContainsKey(k)).Select(k =>
        {
            var parts = k.Split('\0');
            return $"{parts[0]} :: {parts[1]}";
        }).OrderBy(s => s).ToList();
        int unchanged = curFails.Keys.Count(baseFails.Contains);

        return new BaselineDiff(neu.Count, resolved.Count, unchanged, neu, resolved);
    }

    private static string Normalize(string path) =>
        Path.GetFullPath(path).Replace('\\', '/');
}
