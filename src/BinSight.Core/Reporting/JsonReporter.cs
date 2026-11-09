using System.Text.Json;
using BinSight.Core.Analysis;

namespace BinSight.Core.Reporting;

/// <summary>Writes a machine-readable JSON report.</summary>
public sealed class JsonReporter : IReporter
{
    public string FileExtension => "json";

    public void Write(TextWriter writer, AnalysisReport report, bool verbose)
    {
        var dto = BuildDto(report);
        var opts = new JsonSerializerOptions { WriteIndented = true };
        writer.Write(JsonSerializer.Serialize(dto, opts));
    }

    public void WriteBatch(TextWriter writer, BatchAnalysisReport batch)
    {
        var dto = new
        {
            root = batch.RootPath,
            targetCount = batch.TargetCount,
            failureCount = batch.FailureCount,
            reports = batch.Reports.Select(BuildDto).ToArray(),
        };
        var opts = new JsonSerializerOptions { WriteIndented = true };
        writer.Write(JsonSerializer.Serialize(dto, opts));
    }

    private static object BuildDto(AnalysisReport report) => new
    {
        target = report.TargetPath,
        startedUtc = report.StartedUtc,
        finishedUtc = report.FinishedUtc,
        era = report.Era is null ? null : new
        {
            label = report.Era.Label,
            detail = report.Era.Detail,
            approximateYear = report.Era.ApproximateYear,
            isLegacyTooling = report.Era.IsLegacyTooling,
        },
        symbols = new
        {
            availability = report.Symbols.Availability.ToString(),
            summary = report.Symbols.Summary,
            referenced = report.Symbols.PdbPathReferenced,
            found = report.Symbols.PdbPathFound,
            portable = report.Symbols.IsPortablePdb,
            publicHints = report.Symbols.FoundPublicHints,
            advisory = report.Symbols.AdvisoryNotes,
        },
        image = report.Image is null ? null : new
        {
            machine = report.Image.Headers.MachineName,
            is64Bit = report.Image.Headers.Is64Bit,
            isDll = report.Image.Headers.IsDll,
            isManaged = report.Image.IsManaged,
            dllCharacteristics = report.Image.Headers.DllCharacteristics,
            linker = $"{report.Image.Headers.MajorLinkerVersion}.{report.Image.Headers.MinorLinkerVersion:D2}",
            sections = report.Image.Sections.Select(s => new
            {
                name = s.Name,
                rva = s.VirtualAddress,
                size = s.VirtualSize,
                characteristics = s.Characteristics,
            }).ToArray(),
        },
        summary = new
        {
            pass = report.PassCount,
            fail = report.FailCount,
            error = report.ErrorCount,
            notApplicable = report.NotApplicableCount,
        },
        results = report.Results.Select(r =>
        {
            var g = SecurityExplanationFormatter.ResolveGuide(r);
            return new
            {
                check = r.CheckName,
                status = r.Status.ToString(),
                message = r.Message,
                details = r.Details,
                explanation = new
                {
                    purpose = g.Purpose,
                    whyItMatters = g.WhyItMatters,
                    roleInBinary = g.RoleInBinary,
                    statusMeaning = g.MeaningFor(r.Status),
                    ifPasses = g.IfPasses,
                    ifFails = g.IfFails,
                    ifNotApplicable = g.IfNotApplicable,
                    whenFailMayBeExpected = g.WhenFailMayBeExpected,
                    realIssueSignal = g.RealIssueSignal,
                    askTheTeam = g.AskTheTeam,
                },
            };
        }).ToArray(),
    };
}
