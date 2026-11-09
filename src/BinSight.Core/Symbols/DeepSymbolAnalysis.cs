using System.Buffers.Binary;
using BinSight.Core.PE;

namespace BinSight.Core.Symbols;

/// <summary>
/// Deep symbol pass: builds an RVA map (exports + optional DbgHelp) and attributes
/// SafeSEH handlers / GS call sites to names when symbols are present.
/// </summary>
public static class DeepSymbolAnalysis
{
    public sealed record Result(
        PublicSymbolMap Map,
        IReadOnlyList<string> SafeSehHandlers,
        IReadOnlyList<string> GsInstrumentedFunctions,
        string? GsCheckSymbol,
        bool UsedDbgHelp,
        IReadOnlyList<string> Notes);

    public static Result Analyze(PEFile pe, SymbolStatus symbols, string? symbolSearchPath)
    {
        var map = new PublicSymbolMap();
        map.AddRange(pe.ReadExportNameRvas());

        var notes = new List<string>();
        bool usedDbgHelp = false;

        if (symbols.SymbolsAvailable && OperatingSystem.IsWindows())
        {
            if (WindowsDbgHelp.TryLoadModule(pe.FilePath, symbolSearchPath, out var dbgErr))
            {
                usedDbgHelp = true;
                notes.Add("DbgHelp loaded the image + PDB for deep symbol attribution.");
            }
            else if (dbgErr is not null)
            {
                notes.Add($"DbgHelp unavailable for deep pass: {dbgErr}");
            }
        }
        else if (symbols.SymbolsAvailable)
        {
            notes.Add("PDB present but deep DbgHelp attribution requires Windows; using export-table names only.");
        }
        else
        {
            notes.Add("No PDB located — deep SafeSEH/GS function attribution limited to export names.");
        }

        // Resolve SafeSEH handlers.
        var sehNames = new List<string>();
        foreach (uint rva in pe.ReadSafeSehHandlerRvas())
        {
            string? name = null;
            if (usedDbgHelp)
                name = WindowsDbgHelp.TryNameFromRva(rva);
            if (name is null)
                map.TryGetName(rva, out name);
            sehNames.Add(name is null ? $"RVA_0x{rva:X}" : $"{name} (0x{rva:X})");
            if (name is not null)
                map.Add(rva, name);
        }

        // Locate __security_check_cookie for GS call-site scan.
        string? gsCheck = null;
        uint gsRva = 0;
        foreach (var candidate in new[]
                 {
                     "__security_check_cookie", "_security_check_cookie",
                     "@__security_check_cookie@4",
                 })
        {
            if (usedDbgHelp && WindowsDbgHelp.TryFindSymbolRva(candidate, out gsRva))
            {
                gsCheck = candidate;
                break;
            }
            if (map.TryGetRva(candidate, out gsRva))
            {
                gsCheck = candidate;
                break;
            }
        }

        var gsFunctions = new List<string>();
        if (gsRva != 0)
        {
            foreach (uint callRva in FindRelativeCallsTo(pe, gsRva))
            {
                string? owner = null;
                if (usedDbgHelp)
                    owner = WindowsDbgHelp.TryNameFromRva(callRva);
                owner ??= map.FindNearestName(callRva);
                gsFunctions.Add(owner is null
                    ? $"callsite_0x{callRva:X}"
                    : owner);
            }
            gsFunctions = gsFunctions.Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList();
            notes.Add($"Found {gsFunctions.Count} call site(s) to {gsCheck} (heuristic relative-call scan).");
        }
        else
        {
            notes.Add("Could not resolve __security_check_cookie RVA; per-function /GS attribution skipped.");
        }

        if (usedDbgHelp)
            WindowsDbgHelp.Shutdown();

        return new Result(map, sehNames, gsFunctions, gsCheck, usedDbgHelp, notes);
    }

    /// <summary>Scan executable sections for E8 rel32 calls targeting <paramref name="targetRva"/>.</summary>
    public static IReadOnlyList<uint> FindRelativeCallsTo(PEFile pe, uint targetRva)
    {
        var hits = new List<uint>();
        foreach (var section in pe.Sections)
        {
            if (!section.IsExecutable || section.SizeOfRawData == 0) continue;

            if (!pe.TryReadAtRva(section.VirtualAddress, (int)Math.Min(section.VirtualSize == 0 ? section.SizeOfRawData : section.VirtualSize, section.SizeOfRawData), out var code))
                continue;

            // Walk for E8 xx xx xx xx (near relative call).
            for (int i = 0; i + 5 <= code.Length; i++)
            {
                if (code[i] != 0xE8) continue;
                int rel = BinaryPrimitives.ReadInt32LittleEndian(code.Slice(i + 1, 4));
                long callSiteRva = (long)section.VirtualAddress + i;
                long next = callSiteRva + 5;
                long dest = next + rel;
                if (dest == targetRva)
                    hits.Add((uint)callSiteRva);
            }
        }
        return hits;
    }
}
