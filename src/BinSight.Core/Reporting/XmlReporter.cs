using System.Xml;
using BinSight.Core.Analysis;

namespace BinSight.Core.Reporting;

/// <summary>
/// XML report in a schema loosely compatible with BinScope's "Red" format, so that existing
/// pipelines that consumed <c>BinScope /Red</c> output can be migrated with minimal changes.
/// </summary>
public sealed class XmlReporter : IReporter
{
    public string FileExtension => "xml";

    public void Write(TextWriter writer, AnalysisReport report, bool verbose)
    {
        var settings = new XmlWriterSettings { Indent = true, NewLineOnAttributes = false, OmitXmlDeclaration = false };
        using var xml = XmlWriter.Create(writer, settings);
        xml.WriteStartDocument();
        xml.WriteStartElement("BinSightReport");
        xml.WriteAttributeString("target", report.TargetPath);
        xml.WriteAttributeString("startedUtc", report.StartedUtc.ToString("O"));
        xml.WriteAttributeString("finishedUtc", report.FinishedUtc.ToString("O"));

        if (report.Era is not null)
        {
            xml.WriteStartElement("Era");
            xml.WriteAttributeString("label", report.Era.Label);
            xml.WriteAttributeString("legacy", report.Era.IsLegacyTooling.ToString());
            xml.WriteElementString("Detail", report.Era.Detail);
            xml.WriteEndElement();
        }

        xml.WriteStartElement("Symbols");
        xml.WriteAttributeString("availability", report.Symbols.Availability.ToString());
        xml.WriteElementString("Summary", report.Symbols.Summary);
        if (report.Symbols.PdbPathFound is not null)
            xml.WriteElementString("Found", report.Symbols.PdbPathFound);
        xml.WriteEndElement();

        if (report.Image is not null)
        {
            xml.WriteStartElement("Image");
            xml.WriteAttributeString("machine", report.Image.Headers.MachineName);
            xml.WriteAttributeString("is64Bit", report.Image.Headers.Is64Bit.ToString());
            xml.WriteAttributeString("isDll", report.Image.Headers.IsDll.ToString());
            xml.WriteAttributeString("isManaged", report.Image.IsManaged.ToString());
            xml.WriteAttributeString("dllCharacteristics", $"0x{report.Image.Headers.DllCharacteristics:X4}");
            xml.WriteAttributeString("linker",
                $"{report.Image.Headers.MajorLinkerVersion}.{report.Image.Headers.MinorLinkerVersion:D2}");
            xml.WriteEndElement();
        }

        xml.WriteStartElement("Summary");
        xml.WriteAttributeString("pass", report.PassCount.ToString());
        xml.WriteAttributeString("fail", report.FailCount.ToString());
        xml.WriteAttributeString("error", report.ErrorCount.ToString());
        xml.WriteAttributeString("notApplicable", report.NotApplicableCount.ToString());
        xml.WriteEndElement();

        xml.WriteStartElement("Issues");
        foreach (var r in report.Results)
        {
            var g = SecurityExplanationFormatter.ResolveGuide(r);
            xml.WriteStartElement("Issue");
            xml.WriteAttributeString("check", r.CheckName);
            xml.WriteAttributeString("status", r.Status.ToString());
            xml.WriteElementString("Message", r.Message);
            if (r.Details is { Count: > 0 })
            {
                xml.WriteStartElement("Details");
                foreach (var d in r.Details)
                    xml.WriteElementString("Detail", d);
                xml.WriteEndElement();
            }
            xml.WriteStartElement("Explanation");
            xml.WriteElementString("Purpose", g.Purpose);
            xml.WriteElementString("WhyItMatters", g.WhyItMatters);
            xml.WriteElementString("RoleInBinary", g.RoleInBinary);
            xml.WriteElementString("StatusMeaning", g.MeaningFor(r.Status));
            xml.WriteElementString("IfPasses", g.IfPasses);
            xml.WriteElementString("IfFails", g.IfFails);
            xml.WriteElementString("IfNotApplicable", g.IfNotApplicable);
            xml.WriteElementString("WhenFailMayBeExpected", g.WhenFailMayBeExpected);
            xml.WriteElementString("RealIssueSignal", g.RealIssueSignal);
            xml.WriteStartElement("AskTheTeam");
            foreach (var q in g.AskTheTeam)
                xml.WriteElementString("Question", q);
            xml.WriteEndElement();
            xml.WriteEndElement();
            xml.WriteEndElement();
        }
        xml.WriteEndElement();

        xml.WriteEndElement();
        xml.WriteEndDocument();
    }
}
