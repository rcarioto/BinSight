namespace BinSight.Core.PE;

/// <summary>
/// A single <c>IMAGE_IMPORT_DESCRIPTOR</c> and the list of symbols imported from the DLL.
/// </summary>
public sealed record ImportDescriptor(
    string DllName,
    uint OriginalFirstThunkRva,
    uint FirstThunkRva,
    uint TimeDateStamp,
    uint ForwarderChain,
    IReadOnlyList<ImportedSymbol> Symbols);

/// <summary>A single imported function/ordinal.</summary>
public sealed record ImportedSymbol(string? Name, ushort? Hint, ushort? Ordinal)
{
    public bool IsOrdinal => Name is null && Ordinal is not null;
    public string DisplayName => Name ?? $"#{Ordinal}";
}
