using System.Diagnostics;
using System.Text;
using BinSight.Core.Analysis;
using BinSight.Core.Checks;
using BinSight.Core.Reporting;

namespace BinSight;

public sealed class MainForm : Form
{
    private readonly TextBox _pathBox = new() { Dock = DockStyle.Fill };
    private readonly Button _browseFile = new() { Text = "Browse file…", AutoSize = true };
    private readonly Button _browseDir = new() { Text = "Browse folder…", AutoSize = true };
    private readonly CheckBox _recurse = new() { Text = "Recurse folders", AutoSize = true };
    private readonly ComboBox _profile = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
    private readonly Button _scan = new() { Text = "Scan", AutoSize = true };
    private readonly Button _exportHtml = new() { Text = "Save HTML…", AutoSize = true, Enabled = false };
    private readonly Button _openHtml = new() { Text = "Open HTML", AutoSize = true, Enabled = false };
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        AllowUserToAddRows = false,
        AllowUserToDeleteRows = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        MultiSelect = false,
        RowHeadersVisible = false,
    };
    private readonly TextBox _detail = new()
    {
        Dock = DockStyle.Fill,
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Vertical,
        Font = new Font(FontFamily.GenericMonospace, 9f),
    };
    private readonly Label _status = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ProgressBar _progress = new() { Dock = DockStyle.Fill, Style = ProgressBarStyle.Continuous };

    private AnalysisReport? _current;
    private BatchAnalysisReport? _batch;
    private string? _lastHtmlPath;

    public MainForm(string? initialPath = null, string? initialProfile = null)
    {
        Text = "BinSight – PE Security Scanner  ·  Ray Carioto";
        Width = 1100;
        Height = 720;
        MinimumSize = new Size(800, 500);
        StartPosition = FormStartPosition.CenterScreen;

        _profile.Items.AddRange(new object[] { "default", "binscope2014", "modern", "audit" });
        if (!string.IsNullOrWhiteSpace(initialProfile) &&
            _profile.Items.Cast<object>().Any(i => string.Equals(i.ToString(), initialProfile, StringComparison.OrdinalIgnoreCase)))
            _profile.SelectedItem = _profile.Items.Cast<object>()
                .First(i => string.Equals(i.ToString(), initialProfile, StringComparison.OrdinalIgnoreCase));
        else
            _profile.SelectedItem = "default";

        if (!string.IsNullOrWhiteSpace(initialPath))
            _pathBox.Text = initialPath;

        var top = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 72,
            ColumnCount = 6,
            RowCount = 2,
            Padding = new Padding(8),
        };
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        top.Controls.Add(_pathBox, 0, 0);
        top.SetColumnSpan(_pathBox, 1);
        top.Controls.Add(_browseFile, 1, 0);
        top.Controls.Add(_browseDir, 2, 0);
        top.Controls.Add(_recurse, 3, 0);
        top.Controls.Add(_profile, 4, 0);
        top.Controls.Add(_scan, 5, 0);

        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight };
        actions.Controls.Add(_exportHtml);
        actions.Controls.Add(_openHtml);
        top.Controls.Add(actions, 0, 1);
        top.SetColumnSpan(actions, 3);
        top.Controls.Add(_progress, 3, 1);
        top.SetColumnSpan(_progress, 2);
        top.Controls.Add(_status, 5, 1);

        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Status", HeaderText = "Status", FillWeight = 12 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Check", HeaderText = "Check", FillWeight = 22 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Message", HeaderText = "Message", FillWeight = 66 });
        _grid.CellFormatting += GridOnCellFormatting;
        _grid.SelectionChanged += (_, _) => ShowSelectedDetail();
        _grid.CellDoubleClick += GridOnDoubleClick;

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 380,
        };
        split.Panel1.Controls.Add(_grid);
        split.Panel2.Controls.Add(_detail);

        Controls.Add(split);
        Controls.Add(top);

        _browseFile.Click += (_, _) => BrowseFile();
        _browseDir.Click += (_, _) => BrowseDir();
        _scan.Click += async (_, _) => await RunScanAsync();
        _exportHtml.Click += (_, _) => ExportHtml(promptSave: true);
        _openHtml.Click += (_, _) =>
        {
            if (_lastHtmlPath is null) ExportHtml(promptSave: false);
            if (_lastHtmlPath is not null && File.Exists(_lastHtmlPath))
                OpenPath(_lastHtmlPath);
        };

        AllowDrop = true;
        DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
                e.Effect = DragDropEffects.Copy;
        };
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
            {
                _pathBox.Text = files[0];
                _ = RunScanAsync();
            }
        };
    }

    private void BrowseFile()
    {
        using var dlg = new OpenFileDialog
        {
            Title = "Select PE file",
            Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) == DialogResult.OK)
            _pathBox.Text = dlg.FileName;
    }

    private void BrowseDir()
    {
        using var dlg = new FolderBrowserDialog { Description = "Select folder of PE files" };
        if (dlg.ShowDialog(this) == DialogResult.OK)
            _pathBox.Text = dlg.SelectedPath;
    }

    private async Task RunScanAsync()
    {
        string path = _pathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path))
        {
            MessageBox.Show(this, "Choose a file or folder to scan.", "BinSight",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        _scan.Enabled = false;
        _exportHtml.Enabled = false;
        _openHtml.Enabled = false;
        _grid.Rows.Clear();
        _detail.Clear();
        _status.Text = "Scanning…";
        _progress.Value = 0;

        try
        {
            var targets = await Task.Run(() => TargetEnumerator.Expand(path, _recurse.Checked));
            if (targets.Count == 0)
            {
                _status.Text = "No binary files found.";
                return;
            }

            _progress.Maximum = Math.Max(1, targets.Count);
            var checks = ResolveProfile(_profile.SelectedItem?.ToString());
            var scanner = new BinaryScanner(checks);

            var reports = await Task.Run(() => scanner.AnalyzeMany(targets, (done, total, cur, eta) =>
            {
                try
                {
                    BeginInvoke(() =>
                    {
                        _progress.Maximum = Math.Max(1, total);
                        _progress.Value = Math.Min(done, _progress.Maximum);
                        string etaText = eta is null ? "" : $" · ETA {eta.Value:mm\\:ss}";
                        _status.Text = $"[{done}/{total}] {Path.GetFileName(cur)}{etaText}";
                    });
                }
                catch { /* ignore shutdown races */ }
            }));

            _batch = new BatchAnalysisReport(path, reports);
            _current = reports[0];

            // For multi-file, show a pick list of targets in the grid first via failed checks across all;
            // default view: if single file show its checks; if multi show per-target summary then details for first failure-heavy target.
            if (reports.Count == 1)
            {
                BindReport(reports[0]);
            }
            else
            {
                BindBatchOverview(reports);
                var focus = reports.OrderByDescending(r => r.FailCount).First();
                _current = focus;
            }

            _exportHtml.Enabled = true;
            _openHtml.Enabled = true;
            var summary = BatchSummary.From(_batch);
            _status.Text = reports.Count == 1
                ? $"{_current.PassCount} pass · {_current.FailCount} fail · {_current.ErrorCount} error · {_current.NotApplicableCount} n/a"
                : $"{summary.TargetCount} targets · {summary.TargetsWithFailures} with failures";

            // Auto-write HTML beside a temp/user folder for Open HTML convenience.
            ExportHtml(promptSave: false);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Scan failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            _status.Text = "Error";
        }
        finally
        {
            _scan.Enabled = true;
        }
    }

    private void BindBatchOverview(IReadOnlyList<AnalysisReport> reports)
    {
        _grid.Rows.Clear();
        _grid.Columns.Clear();
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Target", HeaderText = "Target", FillWeight = 50 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Fail", HeaderText = "Fail", FillWeight = 10 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Pass", HeaderText = "Pass", FillWeight = 10 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "FailedChecks", HeaderText = "Failed checks", FillWeight = 30 });

        foreach (var r in reports.OrderByDescending(x => x.FailCount).ThenBy(x => x.TargetPath))
        {
            int idx = _grid.Rows.Add(
                r.TargetPath,
                r.FailCount,
                r.PassCount,
                string.Join(", ", r.Results.Where(c => c.Status == CheckStatus.Fail).Select(c => c.CheckName)));
            _grid.Rows[idx].Tag = r;
        }

        _grid.SelectionChanged -= GridBatchSelection;
        _grid.SelectionChanged += GridBatchSelection;
    }

    private void GridBatchSelection(object? sender, EventArgs e)
    {
        if (_grid.CurrentRow?.Tag is AnalysisReport report)
        {
            _current = report;
            // Rebind detail pane to that report's first fail or first row meaning
            var fails = report.Results.Where(r => r.Status == CheckStatus.Fail).ToList();
            var focus = fails.FirstOrDefault() ?? report.Results.FirstOrDefault();
            if (focus is not null)
                _detail.Text = FormatDetail(report, focus);
        }
    }

    private void BindReport(AnalysisReport report)
    {
        _grid.SelectionChanged -= GridBatchSelection;
        _grid.Columns.Clear();
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Status", HeaderText = "Status", FillWeight = 12 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Check", HeaderText = "Check", FillWeight = 22 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Message", HeaderText = "Message", FillWeight = 66 });
        _grid.Rows.Clear();

        foreach (var r in report.Results.OrderBy(r => StatusSort(r.Status)).ThenBy(r => r.CheckName))
        {
            int idx = _grid.Rows.Add(r.Status.ToString(), r.CheckName, r.Message);
            _grid.Rows[idx].Tag = r;
        }

        if (_grid.Rows.Count > 0)
            _grid.Rows[0].Selected = true;
        ShowSelectedDetail();
    }

    private void ShowSelectedDetail()
    {
        if (_current is null) return;
        if (_grid.Columns.Contains("Check") && _grid.CurrentRow?.Tag is CheckResult result)
        {
            _detail.Text = FormatDetail(_current, result);
        }
    }

    private static string FormatDetail(AnalysisReport report, CheckResult r)
    {
        var g = r.Guide ?? CheckDocumentation.GetOrFallback(r.CheckName);
        var sb = new StringBuilder();
        sb.AppendLine($"Target:  {report.TargetPath}");
        if (report.Era is not null)
            sb.AppendLine($"Era:     {report.Era.Label}");
        sb.AppendLine($"Symbols: {report.Symbols.Summary}");
        sb.AppendLine();
        sb.AppendLine($"Check:   {r.CheckName}  [{r.Status}]");
        sb.AppendLine($"Result:  {r.Message}");
        sb.AppendLine();
        sb.AppendLine("Purpose:");
        sb.AppendLine("  " + g.Purpose);
        sb.AppendLine("Why it matters:");
        sb.AppendLine("  " + g.WhyItMatters);
        sb.AppendLine("Role in the binary:");
        sb.AppendLine("  " + g.RoleInBinary);
        sb.AppendLine();
        sb.AppendLine($"What {r.Status} means:");
        sb.AppendLine("  " + g.MeaningFor(r.Status));
        sb.AppendLine();
        sb.AppendLine("When a Fail may be expected:");
        sb.AppendLine("  " + g.WhenFailMayBeExpected);
        sb.AppendLine("Treat as a real issue when:");
        sb.AppendLine("  " + g.RealIssueSignal);
        sb.AppendLine("Ask the application team:");
        foreach (var q in g.AskTheTeam)
            sb.AppendLine("  - " + q);
        sb.AppendLine();
        sb.AppendLine("If Pass:");
        sb.AppendLine("  " + g.IfPasses);
        sb.AppendLine("If Fail:");
        sb.AppendLine("  " + g.IfFails);
        if (r.Details is { Count: > 0 })
        {
            sb.AppendLine();
            sb.AppendLine("Details:");
            foreach (var d in r.Details)
                sb.AppendLine("  - " + d);
        }
        return sb.ToString();
    }

    private void ExportHtml(bool promptSave)
    {
        if (_current is null && _batch is null) return;

        string path;
        if (promptSave)
        {
            using var dlg = new SaveFileDialog
            {
                Filter = "HTML (*.html)|*.html",
                FileName = ReportFileNames.ForTarget(_current?.TargetPath ?? "binsight", "html"),
            };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            path = dlg.FileName;
        }
        else
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "BinSight");
            Directory.CreateDirectory(dir);
            path = Path.Combine(dir, ReportFileNames.ForTarget(_current?.TargetPath ?? "batch", "html"));
        }

        var report = _current ?? _batch!.Reports[0];
        using (var sw = new StreamWriter(path, false, new UTF8Encoding(false)))
            new HtmlReporter().Write(sw, report, verbose: true);

        _lastHtmlPath = path;
        if (promptSave)
            _status.Text = $"HTML saved: {path}";
    }

    private static void OpenPath(string path)
    {
        Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
    }

    private static IEnumerable<ICheck> ResolveProfile(string? profile) => profile?.ToLowerInvariant() switch
    {
        "binscope2014" or "binscope" => CheckRegistry.BinScope2014.Where(c => c.EnabledByDefault)
            .Append(new SymbolsCheck()).Append(new GSSymbolsCheck()),
        "audit" => CheckRegistry.All,
        _ => CheckRegistry.Defaults,
    };

    private static int StatusSort(CheckStatus s) => s switch
    {
        CheckStatus.Fail => 0,
        CheckStatus.Error => 1,
        CheckStatus.Pass => 2,
        _ => 3,
    };

    private void GridOnDoubleClick(object? sender, DataGridViewCellEventArgs e)
    {
        if (e.RowIndex < 0) return;
        if (_grid.Rows[e.RowIndex].Tag is AnalysisReport report)
        {
            _current = report;
            BindReport(report);
            _status.Text = $"{Path.GetFileName(report.TargetPath)} · {report.FailCount} fail · {report.PassCount} pass";
        }
    }

    private void GridOnCellFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
    {
        if (e.ColumnIndex != 0 || e.RowIndex < 0) return;
        var text = e.Value?.ToString();
        e.CellStyle!.ForeColor = text switch
        {
            "Fail" => Color.Firebrick,
            "Error" => Color.DarkGoldenrod,
            "Pass" => Color.DarkGreen,
            _ => SystemColors.ControlText,
        };
    }
}
