using BinSight.Core.Analysis;
using BinSight.Core.Checks;

namespace BinSight.Core.Reporting;

/// <summary>Writes a plain-text report including security explanations for each finding.</summary>
public sealed class ConsoleReporter : IReporter
{
    public string FileExtension => "txt";

    public void Write(TextWriter writer, AnalysisReport report, bool verbose)
    {
        writer.WriteLine($"Target: {report.TargetPath}");
        if (report.Image is not null)
        {
            var h = report.Image.Headers;
            writer.WriteLine($"Image:  {h.MachineName} ({(h.Is64Bit ? "PE32+" : "PE32")}), " +
                             $"{(h.IsDll ? "DLL" : "EXE")}, DllCharacteristics=0x{h.DllCharacteristics:X4}" +
                             (report.Image.IsManaged ? ", managed" : ", native"));
        }
        if (report.Era is not null)
            writer.WriteLine($"Era:    {report.Era.Label} ({report.Era.Detail})");

        writer.WriteLine($"Symbols:{report.Symbols.Summary}");
        if (verbose)
        {
            foreach (var note in report.Symbols.AdvisoryNotes.Take(3))
                writer.WriteLine($"  note: {note}");
        }
        else if (!report.Symbols.SymbolsAvailable)
        {
            writer.WriteLine("  note: Analysis does not require private symbols (unlike BinScope 2014). " +
                             "Providing a PDB via /SymPath enables deeper /GS and CRT helper confirmation.");
        }

        writer.WriteLine($"Scanned {report.Results.Count} check(s) in " +
                         $"{(report.FinishedUtc - report.StartedUtc).TotalMilliseconds:F0} ms.");
        writer.WriteLine(new string('-', 72));

        foreach (var r in report.Results.OrderBy(r => r.CheckName, StringComparer.OrdinalIgnoreCase))
        {
            if (!verbose && r.Status == CheckStatus.Pass) continue;
            WriteLine(writer, r, includeFullExplanation: true);
        }

        if (verbose)
            writer.WriteLine(new string('-', 72));

        writer.WriteLine(
            $"Summary: {report.PassCount} pass, {report.FailCount} fail, " +
            $"{report.ErrorCount} error, {report.NotApplicableCount} n/a.");
    }

    public void WriteBatch(TextWriter writer, BatchAnalysisReport batch, bool verbose)
    {
        writer.WriteLine($"Batch root: {batch.RootPath}");
        writer.WriteLine($"Targets:    {batch.TargetCount}  |  with failures: {batch.FailureCount}");
        writer.WriteLine(new string('=', 72));
        foreach (var report in batch.Reports)
        {
            Write(writer, report, verbose);
            writer.WriteLine();
        }
    }

    private static void WriteLine(TextWriter w, CheckResult r, bool includeFullExplanation)
    {
        string tag = r.Status switch
        {
            CheckStatus.Pass          => "[Pass] ",
            CheckStatus.Fail          => "[Fail] ",
            CheckStatus.Error         => "[Error]",
            CheckStatus.NotApplicable => "[N/A]  ",
            _ => "[??]   ",
        };
        w.WriteLine($"{tag} {r.CheckName,-30} {r.Message}");
        if (r.Details is not null)
        {
            foreach (var d in r.Details)
                w.WriteLine($"         - {d}");
        }

        if (includeFullExplanation)
        {
            foreach (var line in SecurityExplanationFormatter.FormatPlainLines(r))
                w.WriteLine(line);
            w.WriteLine();
        }
    }
}
