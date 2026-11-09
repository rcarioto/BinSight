namespace BinSight.Core.PE;

/// <summary>
/// Best-effort classification of when a PE was likely built, based on toolchain metadata
/// that does not require symbols. Used for reporting context on legacy vs modern binaries.
/// </summary>
public sealed record BinaryEra(
    string Label,
    string Detail,
    int? ApproximateYear,
    bool IsLegacyTooling)
{
    public static BinaryEra Classify(PEFile pe)
    {
        var h = pe.Headers;
        int linker = h.MajorLinkerVersion;
        int? yearFromStamp = null;
        if (h.TimeDateStamp is > 0 and < 0xFFFFFFF0)
        {
            try
            {
                int y = DateTimeOffset.FromUnixTimeSeconds(h.TimeDateStamp).UtcDateTime.Year;
                // Reproducible/.NET deterministic builds often write sentinel stamps far in the future.
                int maxReasonable = DateTime.UtcNow.Year + 1;
                if (y is >= 1990 && y <= maxReasonable)
                    yearFromStamp = y;
            }
            catch
            {
                // ignore invalid stamps (some tools write non-Unix values)
            }
        }

        ushort maxRichBuild = 0;
        var rich = pe.TryReadRichHeader();
        if (rich is not null && rich.Entries.Count > 0)
            maxRichBuild = rich.Entries.Max(e => e.BuildNumber);

        // Prefer linker major as the primary era signal; fall back to timestamp.
        string label;
        int? year;
        bool legacy;

        if (linker >= 14 || maxRichBuild >= 23026)
        {
            // VS2015+ (linker 14.x) covers Win10/Win11 era builds.
            label = maxRichBuild >= 30000 || linker >= 14 && h.MinorLinkerVersion >= 30
                ? "Modern (VS2019+/Win10–Win11 era)"
                : "Modern (VS2015+/Win10 era)";
            year = yearFromStamp ?? (linker >= 14 && h.MinorLinkerVersion >= 30 ? 2022 : 2017);
            legacy = false;
        }
        else if (linker >= 12 || maxRichBuild >= 18000)
        {
            label = "Windows 8 / VS2013 era";
            year = yearFromStamp ?? 2013;
            legacy = false;
        }
        else if (linker >= 10 || maxRichBuild >= 16000)
        {
            label = "Windows 7 / VS2010 era";
            year = yearFromStamp ?? 2010;
            legacy = true;
        }
        else if (linker >= 8 || maxRichBuild >= 14000)
        {
            label = "Vista / VS2005–2008 era";
            year = yearFromStamp ?? 2008;
            legacy = true;
        }
        else if (linker >= 7 || maxRichBuild >= 13000)
        {
            label = "Windows XP / VS2002–2003 era";
            year = yearFromStamp ?? 2003;
            legacy = true;
        }
        else if (linker >= 5 || yearFromStamp is >= 1995 and <= 2001)
        {
            label = "Windows 9x / NT4 / early 2000s era";
            year = yearFromStamp ?? 1999;
            legacy = true;
        }
        else if (pe.IsManaged)
        {
            label = "Managed (.NET) image";
            year = yearFromStamp;
            legacy = false;
        }
        else
        {
            label = yearFromStamp switch
            {
                >= 2021 => "Likely Win11-era (by timestamp)",
                >= 2015 => "Likely Win10-era (by timestamp)",
                >= 2009 => "Likely Win7-era (by timestamp)",
                >= 2001 => "Likely XP/Vista-era (by timestamp)",
                _ => "Unknown / undated tooling",
            };
            year = yearFromStamp;
            legacy = yearFromStamp is < 2015;
        }

        string stamp = yearFromStamp is null
            ? "no reliable TimeDateStamp"
            : $"TimeDateStamp ≈ {yearFromStamp}";
        string detail =
            $"Linker {h.MajorLinkerVersion}.{h.MinorLinkerVersion:D2}; " +
            $"OS ver {h.MajorOperatingSystemVersion}.{h.MinorOperatingSystemVersion}; " +
            $"{stamp}" +
            (maxRichBuild > 0 ? $"; Rich max build {maxRichBuild}" : "");

        return new BinaryEra(label, detail, year, legacy);
    }
}
