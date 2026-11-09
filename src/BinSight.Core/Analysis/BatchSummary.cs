using BinSight.Core.Checks;

namespace BinSight.Core.Analysis;

/// <summary>Roll-up statistics for a multi-file (directory) scan.</summary>
public sealed record BatchSummary(
    int TargetCount,
    int TargetsWithFailures,
    IReadOnlyDictionary<string, CheckRollup> ByCheck,
    IReadOnlyList<OffenderRow> TopOffenders)
{
    public static BatchSummary From(BatchAnalysisReport batch, int topN = 25)
    {
        var byCheck = new Dictionary<string, CheckRollup>(StringComparer.OrdinalIgnoreCase);
        foreach (var report in batch.Reports)
        {
            foreach (var r in report.Results)
            {
                if (!byCheck.TryGetValue(r.CheckName, out var roll))
                {
                    roll = new CheckRollup(r.CheckName, 0, 0, 0, 0);
                    byCheck[r.CheckName] = roll;
                }
                byCheck[r.CheckName] = r.Status switch
                {
                    CheckStatus.Pass => roll with { Pass = roll.Pass + 1 },
                    CheckStatus.Fail => roll with { Fail = roll.Fail + 1 },
                    CheckStatus.Error => roll with { Error = roll.Error + 1 },
                    _ => roll with { NotApplicable = roll.NotApplicable + 1 },
                };
            }
        }

        var offenders = batch.Reports
            .Where(r => r.HasFailures)
            .Select(r => new OffenderRow(
                r.TargetPath,
                r.FailCount,
                string.Join(", ", r.Results.Where(x => x.Status == CheckStatus.Fail).Select(x => x.CheckName).OrderBy(n => n))))
            .OrderByDescending(o => o.FailCount)
            .ThenBy(o => o.TargetPath, StringComparer.OrdinalIgnoreCase)
            .Take(topN)
            .ToList();

        return new BatchSummary(
            batch.TargetCount,
            batch.FailureCount,
            byCheck,
            offenders);
    }
}

public sealed record CheckRollup(string CheckName, int Pass, int Fail, int Error, int NotApplicable)
{
    public int Applicable => Pass + Fail + Error;
    public double FailRatePercent => Applicable == 0 ? 0 : 100.0 * Fail / Applicable;
}

public sealed record OffenderRow(string TargetPath, int FailCount, string FailedChecks);
