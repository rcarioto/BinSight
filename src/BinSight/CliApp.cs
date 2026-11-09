using System.Diagnostics;
using System.Text;
using BinSight.Core.Analysis;
using BinSight.Core.Checks;
using BinSight.Core.Config;
using BinSight.Core.Reporting;

namespace BinSight;

public static class CliApp
{
    public static int Run(string[] args)
    {
        var opt = CommandLineOptions.Parse(args, out string? parseError);

        if (!opt.NoLogo)
            PrintBanner(Console.Out);

        if (parseError is not null)
        {
            Console.Error.WriteLine($"ERROR: {parseError}");
            Console.Error.WriteLine(CommandLineOptions.HelpText);
            return 2;
        }

        if (opt.ShowHelp)
        {
            Console.Out.WriteLine(CommandLineOptions.HelpText);
            return 0;
        }

        if (opt.ListChecks)
        {
            Console.Out.WriteLine("Available checks:");
            foreach (var c in CheckRegistry.All.OrderBy(c => c.Name))
            {
                string def = c.EnabledByDefault ? "default" : "opt-in ";
                Console.Out.WriteLine($"  [{def}] {c.Name,-32} {c.Description}");
            }
            return 0;
        }

        ScanConfig? fileConfig = null;
        if (opt.LoadConfigPath is not null)
        {
            try { fileConfig = ScanConfig.Load(opt.LoadConfigPath); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR: failed to load config: {ex.Message}");
                return 2;
            }
            ApplyConfigDefaults(opt, fileConfig);
        }

        if (opt.SaveConfigPath is not null && string.IsNullOrWhiteSpace(opt.TargetPath))
        {
            SaveConfig(opt);
            Console.Out.WriteLine($"Saved configuration to {opt.SaveConfigPath}");
            return 0;
        }

        if (string.IsNullOrWhiteSpace(opt.TargetPath))
        {
            Console.Error.WriteLine("ERROR: a target file or directory is required.");
            Console.Error.WriteLine(CommandLineOptions.HelpText);
            return 2;
        }

        IReadOnlyList<string> targets;
        try { targets = TargetEnumerator.Expand(opt.TargetPath, opt.Recurse); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            return 2;
        }

        if (targets.Count == 0)
        {
            Console.Error.WriteLine($"ERROR: no binary files found under '{opt.TargetPath}'.");
            return 2;
        }

        IReadOnlyList<ICheck> selected;
        if (fileConfig is not null)
        {
            selected = fileConfig.ResolveChecks(opt.Profile, opt.Checks, opt.SkippedChecks, out var cfgErr);
            if (cfgErr is not null) { Console.Error.WriteLine($"ERROR: {cfgErr}"); return 2; }
            foreach (var f in fileConfig.FailOn)
                if (!opt.FailOnChecks.Contains(f, StringComparer.OrdinalIgnoreCase))
                    opt.FailOnChecks.Add(f);
        }
        else
        {
            selected = ResolveChecks(opt, out var checksError).ToList();
            if (checksError is not null) { Console.Error.WriteLine($"ERROR: {checksError}"); return 2; }
        }

        var ctx = new CheckContext(
            minimumLinkerVersionMajor: opt.MinimumLinkerMajor,
            minimumLinkerVersionMinor: opt.MinimumLinkerMinor,
            minimumCompilerVersionMajor: opt.MinimumCompilerMajor,
            minimumCompilerVersionMinor: opt.MinimumCompilerMinor,
            symbolSearchPath: opt.SymbolSearchPath,
            customRulesPath: opt.CustomRulesPath,
            yaraRulesPath: opt.YaraRulesPath);

        var scanner = new BinaryScanner(selected, ctx);
        bool showProgress = targets.Count > 1 && !Console.IsOutputRedirected;
        var reports = scanner.AnalyzeMany(targets, showProgress ? ProgressToConsole : null);
        if (showProgress) Console.Error.WriteLine();

        var batch = new BatchAnalysisReport(opt.TargetPath, reports);
        var reporter = SelectReporter(opt.Format);

        string? htmlPath = null;
        if (reports.Count > 1)
            htmlPath = WriteBatch(opt, reporter, batch);
        else
            htmlPath = WriteSingle(opt, reporter, reports[0]);

        if (opt.WriteSummaryCsv || reports.Count > 1)
        {
            var summary = BatchSummary.From(batch);
            PrintSummary(summary);
            if (opt.WriteSummaryCsv || opt.Format == OutputFormat.Csv)
            {
                string dir = opt.OutputDirectory
                             ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "BinSight");
                Directory.CreateDirectory(dir);
                string sumPath = Path.Combine(dir, ReportFileNames.ForBatch("summary", "csv"));
                using var sw = new StreamWriter(sumPath, false, new UTF8Encoding(false));
                CsvReporter.WriteSummary(sw, summary);
                Console.Out.WriteLine($"Summary CSV written to: {sumPath}");
            }
        }

        if (opt.SaveBaselinePath is not null)
        {
            BaselineComparer.Save(BaselineComparer.Capture(batch), opt.SaveBaselinePath);
            Console.Out.WriteLine($"Baseline saved to: {opt.SaveBaselinePath}");
        }

        BaselineDiff? diff = null;
        if (opt.BaselinePath is not null)
        {
            try
            {
                var baseline = BaselineComparer.Load(opt.BaselinePath);
                diff = BaselineComparer.Diff(baseline, batch);
                Console.Out.WriteLine(
                    $"Baseline diff: {diff.NewFailures} new failure(s), {diff.ResolvedFailures} resolved, {diff.UnchangedFailures} unchanged.");
                foreach (var line in diff.NewFailureLines.Take(30))
                    Console.Out.WriteLine($"  NEW  {line}");
                foreach (var line in diff.ResolvedFailureLines.Take(15))
                    Console.Out.WriteLine($"  FIXED {line}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR: baseline: {ex.Message}");
                return 2;
            }
        }

        if (opt.SaveConfigPath is not null)
        {
            SaveConfig(opt);
            Console.Out.WriteLine($"Saved configuration to {opt.SaveConfigPath}");
        }

        if (opt.OpenHtml)
        {
            string? toOpen = htmlPath;
            if (toOpen is null && opt.Format == OutputFormat.Html)
                toOpen = ResolveDestination(opt, "html", reports[0].TargetPath);
            if (toOpen is not null && File.Exists(toOpen))
                OpenInBrowser(toOpen);
            else
                Console.Error.WriteLine("NOTE: /OpenHtml requested but no HTML report path was produced. Use /Html.");
        }

        return ComputeExitCode(opt, batch, diff);
    }

    private static void ProgressToConsole(int completed, int total, string path, TimeSpan? eta)
    {
        string etaText = eta is null ? "" : $"  ETA {eta.Value:mm\\:ss}";
        Console.Error.Write($"\r[{completed}/{total}] {Path.GetFileName(path),-40}{etaText}   ");
    }

    private static void PrintSummary(BatchSummary summary)
    {
        Console.Out.WriteLine(new string('=', 72));
        Console.Out.WriteLine($"Batch summary: {summary.TargetCount} target(s), {summary.TargetsWithFailures} with failures");
        Console.Out.WriteLine($"{"Check",-32} {"Pass",6} {"Fail",6} {"Fail%",8}");
        foreach (var roll in summary.ByCheck.Values.OrderByDescending(r => r.Fail).ThenBy(r => r.CheckName).Take(20))
        {
            if (roll.Fail == 0 && roll.Pass == 0) continue;
            Console.Out.WriteLine($"{roll.CheckName,-32} {roll.Pass,6} {roll.Fail,6} {roll.FailRatePercent,7:0.0}%");
        }
        if (summary.TopOffenders.Count > 0)
        {
            Console.Out.WriteLine("Top offenders:");
            foreach (var o in summary.TopOffenders.Take(10))
                Console.Out.WriteLine($"  ({o.FailCount}) {o.TargetPath}");
        }
    }

    private static int ComputeExitCode(CommandLineOptions opt, BatchAnalysisReport batch, BaselineDiff? diff)
    {
        if (diff is not null)
            return diff.NewFailures > 0 ? 1 : 0;

        if (opt.FailOnChecks.Count > 0)
        {
            var failOn = new HashSet<string>(opt.FailOnChecks, StringComparer.OrdinalIgnoreCase);
            bool hit = batch.Reports.Any(r =>
                r.Results.Any(x => x.Status == CheckStatus.Fail && failOn.Contains(x.CheckName)));
            return hit ? 1 : 0;
        }

        return batch.HasFailures ? 1 : 0;
    }

    private static void ApplyConfigDefaults(CommandLineOptions opt, ScanConfig cfg)
    {
        if (opt.SymbolSearchPath is null && cfg.SymbolSearchPath is not null)
            opt.SymbolSearchPath = cfg.SymbolSearchPath;
        if (opt.Profile is null && cfg.Profile is not null)
            opt.Profile = cfg.Profile;
        if (opt.MinimumLinkerMajor == 0 && cfg.MinimumLinkerMajor is int lm)
        {
            opt.MinimumLinkerMajor = lm;
            opt.MinimumLinkerMinor = cfg.MinimumLinkerMinor ?? 0;
        }
        if (opt.MinimumCompilerMajor == 0 && cfg.MinimumCompilerMajor is int cm)
        {
            opt.MinimumCompilerMajor = cm;
            opt.MinimumCompilerMinor = cfg.MinimumCompilerMinor ?? 0;
        }
    }

    private static string? WriteSingle(CommandLineOptions opt, IReporter reporter, AnalysisReport report)
    {
        var destination = ResolveDestination(opt, reporter.FileExtension, report.TargetPath);
        if (destination is null)
        {
            reporter.Write(Console.Out, report, opt.Verbose);
            return null;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        using (var sw = new StreamWriter(destination, false, new UTF8Encoding(false)))
            reporter.Write(sw, report, opt.Verbose);
        Console.Out.WriteLine($"Report written to: {destination}");
        new ConsoleReporter().Write(Console.Out, report, verbose: false);
        return reporter is HtmlReporter ? destination : null;
    }

    private static string? WriteBatch(CommandLineOptions opt, IReporter reporter, BatchAnalysisReport batch)
    {
        string dir = opt.OutputDirectory
                     ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "BinSight");
        Directory.CreateDirectory(dir);
        string? htmlSample = null;

        if (reporter is JsonReporter json)
        {
            string path = opt.LogFile is not null
                ? (Path.IsPathRooted(opt.LogFile) ? opt.LogFile : Path.Combine(dir, opt.LogFile))
                : Path.Combine(dir, ReportFileNames.ForBatch("results", "json"));
            using var sw = new StreamWriter(path, false, new UTF8Encoding(false));
            json.WriteBatch(sw, batch);
            Console.Out.WriteLine($"Batch JSON written to: {path}");
        }
        else if (reporter is SarifReporter sarif)
        {
            string path = Path.Combine(dir, opt.LogFile ?? ReportFileNames.ForBatch("results", "sarif"));
            using var sw = new StreamWriter(path, false, new UTF8Encoding(false));
            sarif.WriteBatch(sw, batch);
            Console.Out.WriteLine($"Batch SARIF written to: {path}");
        }
        else if (reporter is CsvReporter csv)
        {
            string path = Path.Combine(dir, opt.LogFile ?? ReportFileNames.ForBatch("results", "csv"));
            using var sw = new StreamWriter(path, false, new UTF8Encoding(false));
            csv.WriteBatch(sw, batch, opt.Verbose);
            Console.Out.WriteLine($"Batch CSV written to: {path}");
        }
        else
        {
            foreach (var report in batch.Reports)
            {
                string dest = ResolveDestination(opt, reporter.FileExtension, report.TargetPath)
                              ?? Path.Combine(dir, ReportFileNames.ForTarget(report.TargetPath, reporter.FileExtension));
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                using var sw = new StreamWriter(dest, false, new UTF8Encoding(false));
                reporter.Write(sw, report, opt.Verbose);
                Console.Out.WriteLine($"Report written to: {dest}");
                if (reporter is HtmlReporter && htmlSample is null)
                    htmlSample = dest;
            }
        }

        new ConsoleReporter().WriteBatch(Console.Out, batch, verbose: false);
        return htmlSample;
    }

    private static IEnumerable<ICheck> ResolveChecks(CommandLineOptions opt, out string? error)
    {
        error = null;
        IEnumerable<ICheck> baseSet;
        if (opt.Checks.Count > 0)
        {
            var resolved = new List<ICheck>();
            foreach (var name in opt.Checks)
            {
                var c = CheckRegistry.Find(name);
                if (c is null)
                {
                    error = $"Unknown check: {name}.";
                    return Array.Empty<ICheck>();
                }
                if (!resolved.Any(r => r.Name.Equals(c.Name, StringComparison.OrdinalIgnoreCase)))
                    resolved.Add(c);
            }
            baseSet = resolved;
        }
        else
        {
            baseSet = ResolveProfile(opt.Profile, out error);
            if (error is not null) return Array.Empty<ICheck>();
        }

        if (opt.SkippedChecks.Count > 0)
        {
            var skipped = new HashSet<string>(opt.SkippedChecks, StringComparer.OrdinalIgnoreCase);
            baseSet = baseSet.Where(c => !skipped.Contains(c.Name));
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

        error = $"Unknown profile '{profile}'. Use default | binscope2014 | modern | audit.";
        return Array.Empty<ICheck>();
    }

    private static IReporter SelectReporter(OutputFormat fmt) => fmt switch
    {
        OutputFormat.Html => new HtmlReporter(),
        OutputFormat.Xml => new XmlReporter(),
        OutputFormat.Json => new JsonReporter(),
        OutputFormat.PreFast => new XmlReporter(),
        OutputFormat.Csv => new CsvReporter(),
        OutputFormat.Sarif => new SarifReporter(),
        _ => new ConsoleReporter(),
    };

    private static string? ResolveDestination(CommandLineOptions opt, string ext, string targetPath)
    {
        if (opt.Format == OutputFormat.Console && opt.LogFile is null && opt.OutputDirectory is null)
            return null;

        if (opt.LogFile is not null && !Directory.Exists(opt.TargetPath))
        {
            if (opt.OutputDirectory is not null && !Path.IsPathRooted(opt.LogFile))
                return Path.Combine(opt.OutputDirectory, opt.LogFile);
            return opt.LogFile;
        }

        string dir = opt.OutputDirectory
                     ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "BinSight");
        // Explicit /LogFile keeps the user-chosen name; otherwise stamp so reruns do not overwrite.
        return Path.Combine(dir, ReportFileNames.ForTarget(targetPath, ext));
    }

    private static void SaveConfig(CommandLineOptions opt)
    {
        var checks = opt.Checks.Count > 0
            ? opt.Checks.ToArray()
            : CheckRegistry.Defaults.Select(c => c.Name).ToArray();

        using var writer = new StreamWriter(opt.SaveConfigPath!, false, new UTF8Encoding(false));
        writer.WriteLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        writer.WriteLine("<BinSightConfig>");
        if (opt.Profile is not null)
            writer.WriteLine($"  <Profile>{opt.Profile}</Profile>");
        writer.WriteLine("  <Checks>");
        foreach (var c in checks) writer.WriteLine($"    <Check name=\"{c}\" />");
        writer.WriteLine("  </Checks>");
        writer.WriteLine("  <SkippedChecks>");
        foreach (var c in opt.SkippedChecks) writer.WriteLine($"    <Check name=\"{c}\" />");
        writer.WriteLine("  </SkippedChecks>");
        writer.WriteLine("  <FailOn>");
        foreach (var c in opt.FailOnChecks) writer.WriteLine($"    <Check name=\"{c}\" />");
        writer.WriteLine("  </FailOn>");
        if (opt.SymbolSearchPath is not null)
            writer.WriteLine($"  <SymPath>{opt.SymbolSearchPath}</SymPath>");
        if (opt.MinimumLinkerMajor > 0)
            writer.WriteLine($"  <MinimumLinkerVersion>{opt.MinimumLinkerMajor}.{opt.MinimumLinkerMinor}</MinimumLinkerVersion>");
        if (opt.MinimumCompilerMajor > 0)
            writer.WriteLine($"  <MinimumCompilerVersion>{opt.MinimumCompilerMajor}.{opt.MinimumCompilerMinor}</MinimumCompilerVersion>");
        writer.WriteLine("</BinSightConfig>");
    }

    private static void OpenInBrowser(string path)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true,
            };
            Process.Start(psi);
            Console.Out.WriteLine($"Opened: {path}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Could not open browser: {ex.Message}");
        }
    }

    private static void PrintBanner(TextWriter w)
    {
        w.WriteLine("BinSight 1.3 - PE/ELF/Mach-O security scanner (BinScope-compatible), Win10/Win11 + legacy PE support.");
        w.WriteLine("Copyright (C) 2026 Ray Carioto <raymond.carioto@gmail.com>");
        w.WriteLine("License: GNU General Public License v3.0 or later (GPL-3.0-or-later).");
        w.WriteLine();
    }
}
