using System.Text;
using BinSight.Core.PE;

namespace BinSight.Core.Symbols;

/// <summary>
/// Locates PDBs referenced by a PE's CodeView debug directory and extracts best-effort
/// public-symbol hints without requiring the DIA SDK or private type information.
/// </summary>
public static class SymbolResolver
{
    private static readonly string[] InterestingSymbols =
    {
        "__security_init_cookie",
        "__security_check_cookie",
        "__report_gsfailure",
        "__GSHandlerCheck",
        "__GSHandlerCheck_SEH",
        "__GSHandlerCheck_EH",
        "__CxxFrameHandler3",
        "__CxxFrameHandler4",
        "_initterm",
        "_initterm_e",
        "guard_check_icall",
        "_guard_check_icall",
        "__guard_check_icall_fptr",
        "_guard_xfg_check_icall_fptr",
        "__guard_dispatch_icall_fptr",
        "__report_rangecheckfailure",
        "DllMain",
        "WinMain",
        "wWinMain",
    };

    public static SymbolStatus Resolve(PEFile pe, string? symbolSearchPath)
    {
        var cv = pe.TryReadCodeView();
        var notes = new List<string>(SymbolStatus.StandardNoSymbolCapabilities);

        if (cv is null)
        {
            // Some images strip CodeView but leave other debug dirs; still no PDB path.
            notes.Insert(0,
                "Image has no CodeView (RSDS) debug entry, so no PDB path is embedded.");
            return SymbolStatus.None(notes.ToArray());
        }

        string referenced = cv.PdbPath;
        var candidates = BuildCandidatePaths(pe.FilePath, referenced, symbolSearchPath);
        string? found = candidates.FirstOrDefault(File.Exists);

        if (found is null)
        {
            notes.Insert(0,
                $"CodeView references PDB '{referenced}' (GUID={cv.Signature}, age={cv.Age}), but it was not found beside the binary or on /SymPath.");
            return new SymbolStatus(
                SymbolAvailability.ReferencedButMissing,
                referenced,
                null,
                cv.Signature,
                cv.Age,
                false,
                Array.Empty<string>(),
                notes);
        }

        try
        {
            bool portable = IsPortablePdb(found);
            var hints = ProbePublicSymbolHints(found);
            var foundNotes = new List<string>(notes)
            {
                InsertHintSummary(hints, portable),
            };

            return new SymbolStatus(
                SymbolAvailability.Located,
                referenced,
                found,
                cv.Signature,
                cv.Age,
                portable,
                hints,
                foundNotes);
        }
        catch (Exception ex)
        {
            notes.Insert(0, $"Located PDB at '{found}' but failed to probe it: {ex.Message}");
            return new SymbolStatus(
                SymbolAvailability.LocatedButUnreadable,
                referenced,
                found,
                cv.Signature,
                cv.Age,
                false,
                Array.Empty<string>(),
                notes);
        }
    }

    private static string InsertHintSummary(IReadOnlyList<string> hints, bool portable) =>
        hints.Count == 0
            ? (portable
                ? "Portable PDB located; no well-known native GS/CFG symbol strings were found (common for pure managed images)."
                : "Windows PDB located; no well-known public symbol strings were spotted in a lightweight probe. Private symbols may still be present.")
            : $"Lightweight symbol probe found: {string.Join(", ", hints)}.";

    private static IEnumerable<string> BuildCandidatePaths(string pePath, string pdbReferenced, string? symPath)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? p)
        {
            if (!string.IsNullOrWhiteSpace(p))
                seen.Add(Path.GetFullPath(p));
        }

        string peDir = Path.GetDirectoryName(Path.GetFullPath(pePath)) ?? ".";
        string pdbFile = Path.GetFileName(pdbReferenced);

        // 1) Path embedded in CodeView (absolute or relative).
        if (Path.IsPathRooted(pdbReferenced))
            Add(pdbReferenced);
        else
            Add(Path.Combine(peDir, pdbReferenced));

        // 2) Same directory as the binary.
        Add(Path.Combine(peDir, pdbFile));

        // 3) /SymPath entries ('; or path-list separated by ; or : on non-Windows we use ;)
        if (!string.IsNullOrWhiteSpace(symPath))
        {
            foreach (var part in symPath.Split(new[] { ';', Path.PathSeparator },
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                Add(Path.Combine(part, pdbFile));
                Add(Path.Combine(part, pdbReferenced));
                // SymStore-style layout: path/filename/GUID/filename
                // Without a full store walk, also try path/filename directly.
            }
        }

        return seen;
    }

    private static bool IsPortablePdb(string path)
    {
        // Portable PDB starts with "BSJB"
        using var fs = File.OpenRead(path);
        Span<byte> magic = stackalloc byte[4];
        if (fs.Read(magic) < 4) return false;
        return magic[0] == (byte)'B' && magic[1] == (byte)'S' && magic[2] == (byte)'J' && magic[3] == (byte)'B';
    }

    /// <summary>
    /// Best-effort ASCII/UTF-8 scan for well-known public symbol names inside a PDB.
    /// Avoids a full MSF/DIA dependency while still unlocking useful GS/CFG confirmation.
    /// </summary>
    private static IReadOnlyList<string> ProbePublicSymbolHints(string pdbPath)
    {
        // Cap read size to keep memory bounded on huge PDBs.
        const int MaxBytes = 32 * 1024 * 1024;
        byte[] data;
        using (var fs = File.OpenRead(pdbPath))
        {
            int len = (int)Math.Min(fs.Length, MaxBytes);
            data = new byte[len];
            _ = fs.Read(data, 0, len);
        }

        var hits = new List<string>();
        foreach (var sym in InterestingSymbols)
        {
            byte[] needle = Encoding.ASCII.GetBytes(sym);
            if (IndexOf(data, needle) >= 0)
                hits.Add(sym);
        }
        return hits;
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            int j = 0;
            for (; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) break;
            }
            if (j == needle.Length) return i;
        }
        return -1;
    }
}
