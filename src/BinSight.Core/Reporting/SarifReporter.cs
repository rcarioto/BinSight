using System.Text.Json;
using BinSight.Core.Analysis;
using BinSight.Core.Checks;

namespace BinSight.Core.Reporting;

/// <summary>SARIF 2.1.0 reporter for GitHub Code Scanning / Azure DevOps / VS.</summary>
public sealed class SarifReporter : IReporter
{
    public string FileExtension => "sarif";

    public void Write(TextWriter writer, AnalysisReport report, bool verbose)
    {
        WriteMany(writer, new[] { report }, verbose);
    }

    public void WriteBatch(TextWriter writer, BatchAnalysisReport batch, bool verbose = true)
    {
        WriteMany(writer, batch.Reports, verbose);
    }

    private static void WriteMany(TextWriter writer, IReadOnlyList<AnalysisReport> reports, bool verbose)
    {
        var rules = CheckRegistry.All.Select(c =>
        {
            var g = CheckDocumentation.TryGet(c.Name);
            return new
            {
                id = c.Name,
                name = c.Name,
                shortDescription = new { text = c.Description },
                fullDescription = new { text = g?.WhyItMatters ?? c.Description },
                help = new
                {
                    text = g is null
                        ? c.Description
                        : $"{g.Purpose}\n\nPass: {g.IfPasses}\n\nFail: {g.IfFails}\n\n" +
                          $"When Fail may be expected: {g.WhenFailMayBeExpected}\n\n" +
                          $"Real issue when: {g.RealIssueSignal}\n\n" +
                          "Ask the app team:\n" + string.Join("\n", g.AskTheTeam.Select((q, i) => $"{i + 1}. {q}")),
                },
                defaultConfiguration = new { level = "error" },
            };
        }).ToArray();

        var results = new List<object>();
        foreach (var report in reports)
        {
            foreach (var r in report.Results)
            {
                if (r.Status is CheckStatus.Pass or CheckStatus.NotApplicable) continue;
                if (!verbose && r.Status == CheckStatus.Error) { /* still include errors */ }

                string level = r.Status == CheckStatus.Error ? "warning" : "error";
                var g = SecurityExplanationFormatter.ResolveGuide(r);
                results.Add(new
                {
                    ruleId = r.CheckName,
                    level,
                    message = new
                    {
                        text = $"{r.Message}\n\n{g.MeaningFor(r.Status)}\n\n" +
                               $"When Fail may be expected: {g.WhenFailMayBeExpected}\n\n" +
                               $"Real issue when: {g.RealIssueSignal}\n\n" +
                               "Ask the app team:\n" +
                               string.Join("\n", g.AskTheTeam.Select((q, i) => $"{i + 1}. {q}")),
                    },
                    locations = new[]
                    {
                        new
                        {
                            physicalLocation = new
                            {
                                artifactLocation = new { uri = ToUri(report.TargetPath) },
                            },
                        },
                    },
                });
            }
        }

        var sarif = new
        {
            version = "2.1.0",
            schema = "https://json.schemastore.org/sarif-2.1.0.json",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "BinSight",
                            version = "1.1.0",
                            informationUri = "https://github.com/",
                            rules,
                        },
                    },
                    results,
                },
            },
        };

        writer.Write(JsonSerializer.Serialize(sarif, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string ToUri(string path)
    {
        try { return new Uri(Path.GetFullPath(path)).AbsoluteUri; }
        catch { return path.Replace('\\', '/'); }
    }
}
