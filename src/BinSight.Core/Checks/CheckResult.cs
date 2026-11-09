namespace BinSight.Core.Checks;

/// <summary>Outcome of a single check against a single PE image.</summary>
public enum CheckStatus
{
    /// <summary>The check completed and the binary satisfied the requirement.</summary>
    Pass,
    /// <summary>The check completed and the binary violated the requirement.</summary>
    Fail,
    /// <summary>The check could not be performed (missing data, symbols, applicable platform, …).</summary>
    Error,
    /// <summary>The check does not apply to this binary (e.g., SafeSEH on x64) and was skipped.</summary>
    NotApplicable,
}

/// <summary>Result of running a check against one PE file, with optional security education copy.</summary>
public sealed record CheckResult(
    string CheckName,
    CheckStatus Status,
    string Message,
    IReadOnlyList<string>? Details = null,
    CheckSecurityGuide? Guide = null)
{
    /// <summary>Security meaning of <see cref="Status"/> for this check.</summary>
    public string? SecurityMeaning => Guide?.MeaningFor(Status);

    public static CheckResult Pass(string check, string message, IReadOnlyList<string>? details = null) =>
        new(check, CheckStatus.Pass, message, details, CheckDocumentation.TryGet(check));

    public static CheckResult Fail(string check, string message, IReadOnlyList<string>? details = null) =>
        new(check, CheckStatus.Fail, message, details, CheckDocumentation.TryGet(check));

    public static CheckResult Error(string check, string message, IReadOnlyList<string>? details = null) =>
        new(check, CheckStatus.Error, message, details, CheckDocumentation.TryGet(check));

    public static CheckResult NotApplicable(string check, string message) =>
        new(check, CheckStatus.NotApplicable, message, null, CheckDocumentation.TryGet(check));
}
