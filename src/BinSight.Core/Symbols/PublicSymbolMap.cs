namespace BinSight.Core.Symbols;

/// <summary>RVA ↔ name map built from exports, PDB hints, and optional DbgHelp.</summary>
public sealed class PublicSymbolMap
{
    private readonly SortedList<uint, string> _byRva = new();
    private readonly Dictionary<string, uint> _byName = new(StringComparer.Ordinal);

    public int Count => _byRva.Count;

    public void Add(uint rva, string name)
    {
        if (rva == 0 || string.IsNullOrWhiteSpace(name)) return;
        if (!_byRva.ContainsKey(rva))
            _byRva[rva] = name;
        _byName.TryAdd(name, rva);

        // Also index undecorated / stripped leading underscores common on x86.
        if (name.StartsWith('_') && name.Length > 1)
            _byName.TryAdd(name[1..], rva);
    }

    public void AddRange(IEnumerable<KeyValuePair<string, uint>> pairs)
    {
        foreach (var kv in pairs)
            Add(kv.Value, kv.Key);
    }

    public bool TryGetRva(string name, out uint rva) =>
        _byName.TryGetValue(name, out rva);

    public bool TryGetName(uint rva, out string name) =>
        _byRva.TryGetValue(rva, out name!);

    /// <summary>Nearest public at or before <paramref name="rva"/> (for call-site attribution).</summary>
    public string? FindNearestName(uint rva, uint maxDistance = 0x10000)
    {
        if (_byRva.Count == 0) return null;
        if (_byRva.TryGetValue(rva, out var exact)) return exact;

        string? best = null;
        uint bestDelta = maxDistance + 1;
        foreach (var kv in _byRva)
        {
            if (kv.Key > rva) break;
            uint d = rva - kv.Key;
            if (d < bestDelta)
            {
                bestDelta = d;
                best = kv.Value;
            }
        }
        return bestDelta <= maxDistance ? best : null;
    }

    public IReadOnlyList<string> NamesContaining(string fragment) =>
        _byName.Keys.Where(n => n.Contains(fragment, StringComparison.OrdinalIgnoreCase)).ToList();
}
