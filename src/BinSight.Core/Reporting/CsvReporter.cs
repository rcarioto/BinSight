using System.Text;
using BinSight.Core.Analysis;
using BinSight.Core.Checks;

namespace BinSight.Core.Reporting;

/// <summary>CSV export for single or batch results (Excel-friendly).</summary>
public sealed class CsvReporter : IReporter
{
    public string FileExtension => "csv";

    public void Write(TextWriter writer, AnalysisReport report, bool verbose)
    {
        writer.WriteLine("Target,Check,Status,Message,SecurityMeaning");
        foreach (var r in report.Results)
        {
            if (!verbose && r.Status == CheckStatus.Pass) continue;
            WriteRow(writer, report.TargetPath, r);
        }
    }

    public void WriteBatch(TextWriter writer, BatchAnalysisReport batch, bool verbose = true)
    {
        writer.WriteLine("Target,Check,Status,Message,SecurityMeaning");
        foreach (var report in batch.Reports)
        {
            foreach (var r in report.Results)
            {
                if (!verbose && r.Status == CheckStatus.Pass) continue;
                WriteRow(writer, report.TargetPath, r);
            }
        }
    }

    public static void WriteSummary(TextWriter writer, BatchSummary summary)
    {
        writer.WriteLine("Check,Pass,Fail,Error,N/A,FailRatePercent");
        foreach (var roll in summary.ByCheck.Values.OrderByDescending(r => r.Fail).ThenBy(r => r.CheckName))
        {
            writer.WriteLine(string.Join(',',
                Csv(roll.CheckName),
                roll.Pass, roll.Fail, roll.Error, roll.NotApplicable,
                roll.FailRatePercent.ToString("0.0")));
        }
        writer.WriteLine();
        writer.WriteLine("TopOffenders");
        writer.WriteLine("Target,FailCount,FailedChecks");
        foreach (var o in summary.TopOffenders)
            writer.WriteLine($"{Csv(o.TargetPath)},{o.FailCount},{Csv(o.FailedChecks)}");
    }

    private static void WriteRow(TextWriter writer, string target, CheckResult r)
    {
        var meaning = r.SecurityMeaning ?? SecurityExplanationFormatter.ResolveGuide(r).MeaningFor(r.Status);
        writer.WriteLine($"{Csv(target)},{Csv(r.CheckName)},{r.Status},{Csv(r.Message)},{Csv(meaning)}");
    }

    private static string Csv(string s)
    {
        if (s.Contains('"') || s.Contains(',') || s.Contains('\n') || s.Contains('\r'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }
}
