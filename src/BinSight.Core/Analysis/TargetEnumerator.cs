namespace BinSight.Core.Analysis;

/// <summary>Expands a /Target path that may be a file or directory into PE file paths.</summary>
public static class TargetEnumerator
{
    private static readonly HashSet<string> DefaultExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // PE
        ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".efi", ".acm", ".ax", ".drv",
        // ELF / Mach-O
        ".so", ".dylib", ".bundle", ".o", ".elf", ".out",
    };

    /// <summary>
    /// Returns PE candidate paths. If <paramref name="path"/> is a file, returns just that file.
    /// If it is a directory, enumerates matching extensions (optionally recursive).
    /// </summary>
    public static IReadOnlyList<string> Expand(string path, bool recurse, IEnumerable<string>? extensions = null)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("A target path is required.", nameof(path));

        if (File.Exists(path))
            return new[] { Path.GetFullPath(path) };

        if (!Directory.Exists(path))
            throw new FileNotFoundException($"Target path not found: {path}", path);

        var exts = new HashSet<string>(
            (extensions ?? DefaultExtensions).Select(NormalizeExt),
            StringComparer.OrdinalIgnoreCase);

        var option = recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var results = new List<string>();

        foreach (var file in Directory.EnumerateFiles(path, "*", option))
        {
            string ext = Path.GetExtension(file);
            if (exts.Contains(ext))
                results.Add(Path.GetFullPath(file));
        }

        results.Sort(StringComparer.OrdinalIgnoreCase);
        return results;
    }

    private static string NormalizeExt(string e) =>
        e.StartsWith('.') ? e : "." + e;
}
