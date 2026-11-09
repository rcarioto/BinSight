using BinSight.Core.Checks;
using BinSight.Core.PE;
using BinSight.Core.Symbols;

namespace BinSight.Core.Analysis;

/// <summary>Progress callback for multi-file scans.</summary>
/// <param name="completed">Files finished (1-based after each file).</param>
/// <param name="total">Total files.</param>
/// <param name="currentPath">Path just finished (or about to start).</param>
/// <param name="eta">Estimated remaining time, if computable.</param>
public delegate void ScanProgressHandler(int completed, int total, string currentPath, TimeSpan? eta);

/// <summary>Runs a selected set of checks against a PE image and collects results.</summary>
public sealed class Analyzer
{
    private readonly IReadOnlyList<ICheck> _checks;
    private readonly CheckContext _context;

    public Analyzer(IEnumerable<ICheck> checks, CheckContext? context = null)
    {
        _checks  = checks.ToList();
        _context = context ?? new CheckContext();
    }

    public static Analyzer Default(CheckContext? context = null) =>
        new(CheckRegistry.Defaults, context);

    public AnalysisReport Analyze(string path)
    {
        var started = DateTimeOffset.UtcNow;
        PEFile pe;
        try
        {
            pe = PEFile.Load(path);
        }
        catch (Exception ex)
        {
            return new AnalysisReport(
                path, null, started, DateTimeOffset.UtcNow,
                new[] { CheckResult.Error("<load>", $"Failed to load image: {ex.Message}") },
                SymbolStatus.None($"Load failed before symbol resolution: {ex.Message}"),
                null);
        }

        var symbols = SymbolResolver.Resolve(pe, _context.SymbolSearchPath);
        var deep = DeepSymbolAnalysis.Analyze(pe, symbols, _context.SymbolSearchPath);
        var ctx = _context.WithSymbolStatus(symbols).WithDeepSymbols(deep);
        var era = BinaryEra.Classify(pe);

        var results = new List<CheckResult>(_checks.Count);
        foreach (var check in _checks)
        {
            try
            {
                results.Add(check.Run(pe, ctx));
            }
            catch (Exception ex)
            {
                results.Add(CheckResult.Error(check.Name, $"Check threw {ex.GetType().Name}: {ex.Message}"));
            }
        }

        return new AnalysisReport(path, pe, started, DateTimeOffset.UtcNow, results, symbols, era);
    }

    public IReadOnlyList<AnalysisReport> AnalyzeMany(IEnumerable<string> paths, ScanProgressHandler? progress = null)
    {
        var list = paths.ToList();
        var reports = new List<AnalysisReport>(list.Count);
        var sw = System.Diagnostics.Stopwatch.StartNew();

        for (int i = 0; i < list.Count; i++)
        {
            string path = list[i];
            progress?.Invoke(i, list.Count, path, EstimateEta(sw.Elapsed, i, list.Count));
            reports.Add(Analyze(path));
            progress?.Invoke(i + 1, list.Count, path, EstimateEta(sw.Elapsed, i + 1, list.Count));
        }

        return reports;
    }

    private static TimeSpan? EstimateEta(TimeSpan elapsed, int completed, int total)
    {
        if (completed <= 0 || total <= 0 || completed >= total) return null;
        double per = elapsed.TotalSeconds / completed;
        return TimeSpan.FromSeconds(per * (total - completed));
    }
}

public sealed record AnalysisReport(
    string TargetPath,
    PEFile? Image,
    DateTimeOffset StartedUtc,
    DateTimeOffset FinishedUtc,
    IReadOnlyList<CheckResult> Results,
    SymbolStatus Symbols,
    BinaryEra? Era)
{
    public int PassCount => Results.Count(r => r.Status == CheckStatus.Pass);
    public int FailCount => Results.Count(r => r.Status == CheckStatus.Fail);
    public int ErrorCount => Results.Count(r => r.Status == CheckStatus.Error);
    public int NotApplicableCount => Results.Count(r => r.Status == CheckStatus.NotApplicable);
    public bool HasFailures => FailCount > 0;
}

public sealed record BatchAnalysisReport(
    string RootPath,
    IReadOnlyList<AnalysisReport> Reports)
{
    public int TargetCount => Reports.Count;
    public int FailureCount => Reports.Count(r => r.HasFailures);
    public bool HasFailures => FailureCount > 0;
}
