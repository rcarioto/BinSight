using BinSight.Core.Checks;

namespace BinSight.Core.Reporting;

/// <summary>Shared formatting for check security explanations across reporters.</summary>
public static class SecurityExplanationFormatter
{
    public static CheckSecurityGuide ResolveGuide(CheckResult result) =>
        result.Guide ?? CheckDocumentation.GetOrFallback(result.CheckName);

    /// <summary>Plain-text block suitable for console / text logs.</summary>
    public static IEnumerable<string> FormatPlainLines(CheckResult result, string indent = "         ")
    {
        var g = ResolveGuide(result);
        yield return $"{indent}Purpose:  {g.Purpose}";
        yield return $"{indent}Why:      {g.WhyItMatters}";
        yield return $"{indent}In binary:{g.RoleInBinary}";
        yield return $"{indent}Meaning:  {g.MeaningFor(result.Status)}";

        if (result.Status is CheckStatus.Fail or CheckStatus.Error)
        {
            yield return $"{indent}When Fail may be expected: {g.WhenFailMayBeExpected}";
            yield return $"{indent}Real issue when: {g.RealIssueSignal}";
            yield return $"{indent}Ask the app team:";
            foreach (var q in g.AskTheTeam)
                yield return $"{indent}  - {q}";
        }
    }
}
