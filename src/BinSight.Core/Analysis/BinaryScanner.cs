using BinSight.Core.Checks;
using BinSight.Core.Formats;
using BinSight.Core.Rules;
using BinSight.Core.Symbols;

namespace BinSight.Core.Analysis;

/// <summary>
/// Format-detecting scanner: PE (full check set), ELF, or Mach-O (unix mitigation analogues),
/// plus optional custom / YARA rules for any format.
/// </summary>
public sealed class BinaryScanner
{
    private readonly IReadOnlyList<ICheck> _peChecks;
    private readonly CheckContext _context;

    public BinaryScanner(IEnumerable<ICheck> peChecks, CheckContext? context = null)
    {
        _peChecks = peChecks.ToList();
        _context = context ?? new CheckContext();
    }

    public AnalysisReport Analyze(string path)
    {
        var started = DateTimeOffset.UtcNow;
        BinaryFormat fmt;
        try { fmt = BinaryFormatDetector.Detect(path); }
        catch (Exception ex)
        {
            return ErrorReport(path, started, $"Failed to detect format: {ex.Message}");
        }

        return fmt switch
        {
            BinaryFormat.Pe => new Analyzer(_peChecks, _context).Analyze(path),
            BinaryFormat.Elf => AnalyzeElf(path, started),
            BinaryFormat.MachO => AnalyzeMachO(path, started),
            _ => ErrorReport(path, started, "Unrecognized binary format (not PE, ELF, or Mach-O)."),
        };
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

    private AnalysisReport AnalyzeElf(string path, DateTimeOffset started)
    {
        try
        {
            var elf = ElfFile.Load(path);
            var results = UnixChecks.RunElf(elf).ToList();
            AppendFileRules(path, results);
            return new AnalysisReport(path, null, started, DateTimeOffset.UtcNow, results,
                SymbolStatus.None("ELF image — PE PDB symbol analysis does not apply."),
                null);
        }
        catch (Exception ex)
        {
            return ErrorReport(path, started, $"ELF parse failed: {ex.Message}");
        }
    }

    private AnalysisReport AnalyzeMachO(string path, DateTimeOffset started)
    {
        try
        {
            var macho = MachOFile.Load(path);
            var results = UnixChecks.RunMachO(macho).ToList();
            AppendFileRules(path, results);
            return new AnalysisReport(path, null, started, DateTimeOffset.UtcNow, results,
                SymbolStatus.None("Mach-O image — PE PDB symbol analysis does not apply."),
                null);
        }
        catch (Exception ex)
        {
            return ErrorReport(path, started, $"Mach-O parse failed: {ex.Message}");
        }
    }

    private void AppendFileRules(string path, List<CheckResult> results)
    {
        if (!string.IsNullOrWhiteSpace(_context.CustomRulesPath) && File.Exists(_context.CustomRulesPath))
        {
            try
            {
                var set = CustomRuleSet.Load(_context.CustomRulesPath);
                results.AddRange(set.EvaluateFile(path));
            }
            catch (Exception ex)
            {
                results.Add(CheckResult.Error("CustomRulesCheck", ex.Message));
            }
        }
    }

    private static AnalysisReport ErrorReport(string path, DateTimeOffset started, string message) =>
        new(path, null, started, DateTimeOffset.UtcNow,
            new[] { CheckResult.Error("<load>", message) },
            SymbolStatus.None(message),
            null);

    private static TimeSpan? EstimateEta(TimeSpan elapsed, int completed, int total)
    {
        if (completed <= 0 || total <= 0 || completed >= total) return null;
        double per = elapsed.TotalSeconds / completed;
        return TimeSpan.FromSeconds(per * (total - completed));
    }
}
