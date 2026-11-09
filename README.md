# BinSight

**BinSight** is a modern, open re-implementation of Microsoft's [BinScope 2014](https://www.microsoft.com/en-us/download/details.aspx?id=44995) binary security scanner for **Windows 10 and Windows 11**. It analyzes **PE32 / PE32+** (including legacy Windows-era binaries), plus **ELF** and **Mach-O** mitigation checks. **One EXE** covers both the graphical UI and the command-line scanner.

**Author:** Ray Carioto \<raymond.carioto@gmail.com\>  
**License:** GNU GPL v3.0 or later — see [LICENSE](LICENSE).

## Download / package

```text
publish/release/BinSight-1.3.0-win-x64.zip
publish/release/BinSight-1.3.0-win-x64.zip.sha256
```

Self-contained — **no .NET install required**. Verify with:

```bat
certutil -hashfile BinSight-1.3.0-win-x64.zip SHA256
```

Rebuild: `./scripts/pack-release.sh 1.3.0`

## GUI + CLI (same binary)

| How you start it | Mode |
|---|---|
| Double-click `BinSight.exe` | **GUI** |
| `BinSight.exe /gui` | **GUI** |
| `BinSight.exe /gui /Target C:\app.exe` | **GUI** with path filled in |
| `BinSight.exe /Target C:\app.exe /Verbose` | **CLI** |
| `BinSight.exe /ListChecks` | **CLI** |

### GUI
Browse or drag a file/folder → **Scan** → review the grid + security explanations (including triage / ask-the-team notes) → **Save HTML** / **Open HTML**.

### CLI examples

```bat
BinSight.exe /Target C:\Windows\System32\notepad.exe /Verbose
BinSight.exe /Target C:\build\out /Recurse /Html /OpenHtml /OutDir .\reports
BinSight.exe /Target C:\build\out /Recurse /Sarif /SummaryCsv /SaveBaseline baseline.json
BinSight.exe /Baseline baseline.json /Target C:\build\out /Recurse /FailOn CFGCheck,CETCheck
BinSight.exe /Config team-policy.xml /Target app.exe
BinSight.exe /Target app.exe /SymPath C:\symbols
BinSight.exe /Target app.exe /Rules examples\custom-rules.sample.json
BinSight.exe /Target app.exe /Yara examples\sample.yar
BinSight.exe /Target .\libfoo.so /Verbose
BinSight.exe /Target .\MyApp.dylib /Verbose
```

## Highlights

- **PE32 + PE32+**, plus **ELF** (PIE, NX stack, RELRO, stack canary, Fortify hints) and **Mach-O** (MH_PIE, stack exec, canary, code-signature indicators)
- Works **without private PDBs**; with a matching PDB on Windows, DbgHelp deep-pass names **SafeSEH handlers** and attributes **/GS call sites**
- Custom policy: `/Rules` JSON (banned imports/sections/patterns) and `/Yara` (yara CLI if installed, else strings/hex subset)
- Reports: Console, HTML, JSON, XML, CSV, SARIF — each finding includes purpose, why it matters, triage (expected noise vs real issue), and ask-the-team questions
- `/Recurse` with progress + ETA, `/Config`, `/FailOn`, baseline diff
- .NET 8 target with roll-forward to 9/10 when using framework-dependent builds

### Custom rules / YARA

Sample files live under `examples/`:

- `examples/custom-rules.sample.json`
- `examples/sample.yar`

```bat
BinSight.exe /Target app.exe /Rules examples\custom-rules.sample.json
BinSight.exe /Target app.exe /Yara examples\sample.yar
```

## Build from source

```bash
dotnet build -c Release
dotnet test  -c Release
./scripts/pack-release.sh 1.3.0
```

Requires a .NET **8+** SDK. The app targets `net8.0-windows` (WinForms + CLI).
