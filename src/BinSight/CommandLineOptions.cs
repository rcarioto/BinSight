namespace BinSight;

public enum OutputFormat
{
    Console,
    Html,
    Xml,
    Json,
    PreFast,
    Csv,
    Sarif,
}

/// <summary>Parsed, validated command-line options.</summary>
public sealed class CommandLineOptions
{
    public string? TargetPath { get; set; }
    public string? SymbolSearchPath { get; set; }
    public List<string> Checks { get; } = new();
    public List<string> SkippedChecks { get; } = new();
    public List<string> FailOnChecks { get; } = new();
    public bool Verbose { get; set; }
    public bool NoLogo { get; set; }
    public bool ListChecks { get; set; }
    public bool ShowHelp { get; set; }
    public string? LogFile { get; set; }
    public string? OutputDirectory { get; set; }
    public string? SaveConfigPath { get; set; }
    public string? LoadConfigPath { get; set; }
    public OutputFormat Format { get; set; } = OutputFormat.Console;
    public bool WriteXslt { get; set; }
    public bool Recurse { get; set; }
    public string? Profile { get; set; }
    public bool OpenHtml { get; set; }
    public string? BaselinePath { get; set; }
    public string? SaveBaselinePath { get; set; }
    public bool WriteSummaryCsv { get; set; }
    public string? CustomRulesPath { get; set; }
    public string? YaraRulesPath { get; set; }

    public int MinimumLinkerMajor { get; set; }
    public int MinimumLinkerMinor { get; set; }
    public int MinimumCompilerMajor { get; set; }
    public int MinimumCompilerMinor { get; set; }

    public static CommandLineOptions Parse(string[] args, out string? error)
    {
        error = null;
        var opt = new CommandLineOptions();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            bool isFlag = a.StartsWith("-") || a.StartsWith("/");
            string key = isFlag ? a.TrimStart('-', '/') : a;

            if (!isFlag)
            {
                if (opt.TargetPath is null) opt.TargetPath = a;
                else { error = $"Unexpected positional argument: {a}"; return opt; }
                continue;
            }

            bool TryNext(out string value)
            {
                if (i + 1 >= args.Length) { value = ""; return false; }
                value = args[++i];
                return true;
            }

            switch (key.ToLowerInvariant())
            {
                case "?": case "h": case "help": opt.ShowHelp = true; break;
                case "nologo": opt.NoLogo = true; break;
                case "v": case "verbose": opt.Verbose = true; break;
                case "lc": case "listchecks": opt.ListChecks = true; break;
                case "r": case "recurse": opt.Recurse = true; break;
                case "gui": break; // handled by Program entry; ignore if CLI path still sees it
                case "open": case "openhtml": opt.OpenHtml = true; break;
                case "summarycsv": opt.WriteSummaryCsv = true; break;
                case "c": case "checks":
                    if (!TryNext(out var cv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.Checks.Add(cv); break;
                case "e": case "skippedchecks":
                    if (!TryNext(out var sv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.SkippedChecks.Add(sv); break;
                case "failon":
                    if (!TryNext(out var fo)) { error = $"Missing value for /{key}."; return opt; }
                    foreach (var part in fo.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        opt.FailOnChecks.Add(part);
                    break;
                case "t": case "target":
                    if (!TryNext(out var tv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.TargetPath = tv; break;
                case "s": case "sympath":
                    if (!TryNext(out var spv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.SymbolSearchPath = spv; break;
                case "l": case "logfile":
                    if (!TryNext(out var lv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.LogFile = lv; break;
                case "d": case "outdir":
                    if (!TryNext(out var ov)) { error = $"Missing value for /{key}."; return opt; }
                    opt.OutputDirectory = ov; break;
                case "html": opt.Format = OutputFormat.Html; break;
                case "red": opt.Format = OutputFormat.Xml; break;
                case "json": opt.Format = OutputFormat.Json; break;
                case "csv": opt.Format = OutputFormat.Csv; break;
                case "sarif": opt.Format = OutputFormat.Sarif; break;
                case "pf": case "prefast": opt.Format = OutputFormat.PreFast; break;
                case "x": case "xslt": opt.WriteXslt = true; break;
                case "save": case "saveconfig":
                    if (!TryNext(out var scv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.SaveConfigPath = scv; break;
                case "config": case "loadconfig":
                    if (!TryNext(out var lcv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.LoadConfigPath = lcv; break;
                case "profile":
                    if (!TryNext(out var pv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.Profile = pv; break;
                case "baseline":
                    if (!TryNext(out var bv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.BaselinePath = bv; break;
                case "savebaseline":
                    if (!TryNext(out var sbv)) { error = $"Missing value for /{key}."; return opt; }
                    opt.SaveBaselinePath = sbv; break;
                case "rules": case "customrules":
                    if (!TryNext(out var rules)) { error = $"Missing value for /{key}."; return opt; }
                    opt.CustomRulesPath = rules; break;
                case "yara":
                    if (!TryNext(out var yara)) { error = $"Missing value for /{key}."; return opt; }
                    opt.YaraRulesPath = yara; break;
                case "minimumlinkerversion":
                    if (!TryNext(out var mlv)) { error = $"Missing value for /{key}."; return opt; }
                    if (!TryParseVersion(mlv, out var mlMaj, out var mlMin))
                    { error = $"Invalid version for /MinimumLinkerVersion: {mlv}"; return opt; }
                    opt.MinimumLinkerMajor = mlMaj; opt.MinimumLinkerMinor = mlMin; break;
                case "minimumcompilerversion":
                    if (!TryNext(out var mcv)) { error = $"Missing value for /{key}."; return opt; }
                    if (!TryParseVersion(mcv, out var mcMaj, out var mcMin))
                    { error = $"Invalid version for /MinimumCompilerVersion: {mcv}"; return opt; }
                    opt.MinimumCompilerMajor = mcMaj; opt.MinimumCompilerMinor = mcMin; break;
                default:
                    error = $"Unknown option: {a}";
                    return opt;
            }
        }
        return opt;
    }

    private static bool TryParseVersion(string value, out int major, out int minor)
    {
        major = 0; minor = 0;
        var parts = value.Split('.', 2);
        if (!int.TryParse(parts[0], out major)) return false;
        if (parts.Length == 2 && !int.TryParse(parts[1], out minor)) return false;
        return true;
    }

    public static string HelpText =>
        """
        BinSight - binary security scanner for PE, ELF, and Mach-O images.

        Usage:
          BinSight                         Launch the graphical UI
          BinSight /gui [/Target path]     Launch the UI (optional path prefill)
          BinSight [options] <target>      CLI scan mode
          BinSight /Target <path> [options]

        Common:
          /Target <path>            File OR directory (PE / ELF / Mach-O).
          /Recurse (/r)             Recurse when /Target is a directory.
          /Checks <name>            Run only named check(s). Repeatable.
          /SkippedChecks <name>     Skip named check(s). Repeatable.
          /FailOn <a,b,c>           Exit 1 only if these checks fail (else soft).
          /ListChecks               List checks and exit.
          /Profile <name>           default | binscope2014 | modern | audit
          /Config <file>            Load BinSightConfig XML policy.
          /SymPath <path>           PDB search path(s).
          /Rules <file.json>        Custom banned-import/section/pattern rules.
          /Yara <file-or-dir>       YARA rules (uses yara CLI if installed).

        Output:
          /Html /Red /Json /Csv /Sarif /PREfast
          /LogFile <file>  /OutDir <dir>  /Verbose  /NoLogo
          /OpenHtml                 After /Html, open the report in the default browser.
          /SummaryCsv               Also write batch summary CSV (multi-target).

        Baseline / CI:
          /SaveBaseline <file>      Write current results as baseline JSON.
          /Baseline <file>          Diff against baseline; new failures affect exit code.

        Policy:
          /MinimumLinkerVersion <maj.min>
          /MinimumCompilerVersion <maj.min>
          /SaveConfig <file>

        Exit codes:
          0 = clean (per FailOn/baseline rules), 1 = failures, 2 = usage error.
        """;
}
