namespace BinSight;

/// <summary>Builds non-colliding report filenames that include a local timestamp.</summary>
internal static class ReportFileNames
{
    /// <summary>
    /// Example: <c>notepad.binsight.2026-11-05_123045.html</c>
    /// </summary>
    public static string ForTarget(string? targetPath, string extension, DateTimeOffset? when = null)
    {
        string baseName = string.IsNullOrWhiteSpace(targetPath)
            ? "binsight"
            : Path.GetFileNameWithoutExtension(targetPath);
        return $"{baseName}.binsight.{Stamp(when)}.{NormalizeExt(extension)}";
    }

    /// <summary>
    /// Example: <c>batch.binsight.2026-11-05_123045.json</c>
    /// </summary>
    public static string ForBatch(string kind, string extension, DateTimeOffset? when = null) =>
        $"batch.{kind}.binsight.{Stamp(when)}.{NormalizeExt(extension)}";

    public static string Stamp(DateTimeOffset? when = null)
    {
        var t = when ?? DateTimeOffset.Now;
        return t.ToString("yyyy-MM-dd_HHmmss");
    }

    private static string NormalizeExt(string extension) =>
        extension.TrimStart('.');
}
