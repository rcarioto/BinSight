using BinSight.Core.Analysis;

namespace BinSight.Core.Reporting;

/// <summary>Contract for anything that renders an <see cref="AnalysisReport"/>.</summary>
public interface IReporter
{
    /// <summary>Write the report to <paramref name="writer"/>.</summary>
    void Write(TextWriter writer, AnalysisReport report, bool verbose);

    /// <summary>Preferred file extension for this format (without the dot).</summary>
    string FileExtension { get; }
}
