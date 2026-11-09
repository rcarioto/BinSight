namespace BinSight.Core.Symbols;

/// <summary>How private/public symbols relate to the scanned image.</summary>
public enum SymbolAvailability
{
    /// <summary>No CodeView debug directory – binary has no PDB reference.</summary>
    NoneReferenced,
    /// <summary>CodeView names a PDB, but it was not found on disk / SymPath.</summary>
    ReferencedButMissing,
    /// <summary>A PDB (or portable PDB) was located and is usable for enhanced insights.</summary>
    Located,
    /// <summary>A PDB was located but could not be opened / matched.</summary>
    LocatedButUnreadable,
}

/// <summary>
/// Result of symbol discovery. BinSight performs a full native PE security analysis
/// <b>without</b> symbols; this status explains what additional depth symbols would unlock.
/// </summary>
public sealed record SymbolStatus(
    SymbolAvailability Availability,
    string? PdbPathReferenced,
    string? PdbPathFound,
    Guid? CodeViewGuid,
    uint? CodeViewAge,
    bool IsPortablePdb,
    IReadOnlyList<string> FoundPublicHints,
    IReadOnlyList<string> AdvisoryNotes)
{
    public bool SymbolsAvailable =>
        Availability is SymbolAvailability.Located;

    /// <summary>Human-readable one-liner for console / HTML banners.</summary>
    public string Summary => Availability switch
    {
        SymbolAvailability.NoneReferenced =>
            "No PDB referenced in the image. Full header/section/import analysis still applies without symbols.",
        SymbolAvailability.ReferencedButMissing =>
            $"PDB referenced ('{PdbPathReferenced}') but not found. Analysis continued without symbols.",
        SymbolAvailability.Located =>
            $"Symbols located at '{PdbPathFound}'. Enhanced insights enabled; private types would deepen /GS coverage analysis further.",
        SymbolAvailability.LocatedButUnreadable =>
            $"PDB found at '{PdbPathFound}' but could not be fully read. Analysis continued with header-level checks.",
        _ => "Symbol status unknown.",
    };

    public static SymbolStatus None(params string[] notes) =>
        new(SymbolAvailability.NoneReferenced, null, null, null, null, false,
            Array.Empty<string>(), notes);

    /// <summary>
    /// Standard advisory explaining what BinSight already covers without symbols, and what
    /// private symbols would additionally enable (the gap BinScope 2014 left open).
    /// </summary>
    public static IReadOnlyList<string> StandardNoSymbolCapabilities { get; } = new[]
    {
        "Without symbols BinSight still validates: ASLR/DYNAMICBASE, DEP/NXCOMPAT, High-Entropy VA, CFG, CET, SafeSEH, W^X, shared sections, IAT executability, Load Config /GS cookie presence & default value, delay-load IAT guards, Authenticode presence, embedded UAC manifest, Rich/compiler version, banned imports (VB6/RSA32/ATL), and relocation stripping.",
        "With public symbols / exports BinSight can confirm CRT GS helpers and map some addresses by name.",
        "With a matching PDB on Windows, BinSight uses DbgHelp for a deeper pass: name SafeSEH handler RVAs and attribute functions that call __security_check_cookie (heuristic coverage).",
    };
}
