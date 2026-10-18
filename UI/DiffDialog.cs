using System;
using System.Drawing;
using System.Windows.Forms;
using HashCheckSentinel.Core;

namespace HashCheckSentinel.UI
{
    public sealed class DiffDialog : Form
    {
        private readonly TabControl _tabs;
        private readonly TabPage _tabText;
        private readonly TabPage _tabBinary;
        private readonly RichTextBox _rtb;

        public DiffDialog(
            string relativePath,
            string oldSha,
            string newSha,
            DiffReport diffReport,
            BinaryDeltaReport binaryReport,
            bool isBinary = false,
            string currentTextContent = null)
        {
            bool isOfficeDoc = OfficeTextExtractor.IsOfficeDocument(relativePath);
            bool hasTextDiff = diffReport != null && diffReport.Lines.Count > 0;

            Text = $"Forensic Inspection: {relativePath}";
            Width = 960;
            Height = 650;
            MinimumSize = new Size(800, 520);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Color.FromArgb(15, 23, 42);
            ForeColor = Color.White;

            // 1. Top Header Panel
            var header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 98,
                BackColor = Color.FromArgb(15, 23, 42),
                Padding = new Padding(18, 12, 18, 8)
            };

            var pnlBadgeRow = new FlowLayoutPanel
            {
                Location = new Point(18, 10),
                Size = new Size(Width - 40, 28),
                BackColor = Color.Transparent,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                WrapContents = false
            };

            var lblTitle = new Label
            {
                Text = $"📁 {relativePath}",
                Font = new Font("Segoe UI", 11.5F, FontStyle.Bold),
                ForeColor = Color.White,
                AutoSize = true,
                Margin = new Padding(0, 0, 10, 0)
            };

            var lblBadge = new Label
            {
                AutoSize = true,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Padding = new Padding(6, 3, 6, 3),
                Margin = new Padding(0, 2, 0, 0)
            };

            if (isOfficeDoc)
            {
                lblBadge.Text = "📦 Microsoft Word Document (.docx)";
                lblBadge.BackColor = Color.FromArgb(30, 58, 138);
                lblBadge.ForeColor = Color.FromArgb(191, 219, 254);
            }
            else if (isBinary)
            {
                lblBadge.Text = "⚙️ Binary Data / Archive";
                lblBadge.BackColor = Color.FromArgb(88, 28, 135);
                lblBadge.ForeColor = Color.FromArgb(233, 213, 255);
            }
            else
            {
                lblBadge.Text = "📄 Text Document / Script";
                lblBadge.BackColor = Color.FromArgb(6, 78, 59);
                lblBadge.ForeColor = Color.FromArgb(167, 243, 208);
            }

            pnlBadgeRow.Controls.Add(lblTitle);
            pnlBadgeRow.Controls.Add(lblBadge);

            var lblOldHash = new Label
            {
                Text = $"Baseline SHA-256 : {oldSha}",
                Font = new Font("Consolas", 8.5F),
                ForeColor = Color.FromArgb(147, 197, 253),
                Left = 20,
                Top = 46,
                AutoSize = true
            };

            var lblNewHash = new Label
            {
                Text = $"Current  SHA-256 : {newSha}",
                Font = new Font("Consolas", 8.5F),
                ForeColor = string.Equals(oldSha, newSha, StringComparison.OrdinalIgnoreCase) ? Color.FromArgb(134, 239, 172) : Color.Gold,
                Left = 20,
                Top = 68,
                AutoSize = true
            };

            header.Controls.AddRange(new Control[] { pnlBadgeRow, lblOldHash, lblNewHash });

            // 2. Tab Control
            _tabs = new TabControl
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 9.5F)
            };

            // TAB 1: Line-by-Line Content Diff
            _tabText = new TabPage("Line-by-Line Content Diff") { BackColor = Color.FromArgb(18, 18, 18) };
            _rtb = new RichTextBox
            {
                Dock = DockStyle.Fill,
                Font = new Font("Consolas", 9.5F),
                BackColor = Color.FromArgb(18, 18, 18),
                ForeColor = Color.White,
                ReadOnly = true,
                WordWrap = false,
                BorderStyle = BorderStyle.None
            };

            if (hasTextDiff)
            {
                if (isOfficeDoc)
                {
                    _rtb.SelectionColor = Color.FromArgb(125, 211, 252);
                    _rtb.AppendText("// 📝 MICROSOFT WORD CONTENT DIFF: Extracted from word/document.xml\n");
                }
                RenderDiff(_rtb, diffReport);
            }
            else
            {
                RenderNonTextExplanation(_rtb, relativePath, oldSha, newSha, binaryReport, isOfficeDoc, isBinary, currentTextContent);
            }

            _tabText.Controls.Add(_rtb);
            _tabs.TabPages.Add(_tabText);

            // TAB 2: Forensic Metadata & Heuristics
            if (binaryReport != null)
            {
                _tabBinary = new TabPage("Forensic Metadata & Heuristics") { BackColor = Color.FromArgb(15, 23, 42) };
                var pnlMeta = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20) };

                // Assessment Card
                var pnlCard = new Panel
                {
                    Dock = DockStyle.Top,
                    Height = 72,
                    BackColor = Color.FromArgb(30, 41, 59),
                    Padding = new Padding(16, 12, 16, 12)
                };

                var lblAssessmentTitle = new Label
                {
                    Text = "FORENSIC INTEGRITY ASSESSMENT:",
                    Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                    ForeColor = Color.FromArgb(148, 163, 184),
                    AutoSize = true,
                    Location = new Point(14, 10)
                };

                var lblAssessment = new Label
                {
                    Text = binaryReport.Assessment,
                    Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
                    ForeColor = binaryReport.EntropyDelta > 1.0 || binaryReport.TimestompingDetected ? Color.OrangeRed : (isOfficeDoc ? Color.FromArgb(147, 197, 253) : Color.LightGreen),
                    AutoSize = true,
                    Location = new Point(14, 32)
                };

                pnlCard.Controls.Add(lblAssessmentTitle);
                pnlCard.Controls.Add(lblAssessment);

                // Metadata DataGridView
                var metaGrid = new DataGridView
                {
                    Dock = DockStyle.Fill,
                    BackgroundColor = Color.FromArgb(15, 23, 42),
                    ForeColor = Color.White,
                    AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                    ReadOnly = true,
                    AllowUserToAddRows = false,
                    RowHeadersVisible = false,
                    EnableHeadersVisualStyles = false,
                    BorderStyle = BorderStyle.None,
                    CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
                    GridColor = Color.FromArgb(30, 41, 59),
                    ColumnHeadersHeight = 32,
                    RowTemplate = { Height = 28 }
                };

                metaGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(30, 41, 59);
                metaGrid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(148, 163, 184);
                metaGrid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9F, FontStyle.Bold);

                metaGrid.DefaultCellStyle.BackColor = Color.FromArgb(15, 23, 42);
                metaGrid.DefaultCellStyle.ForeColor = Color.White;
                metaGrid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(37, 99, 235);
                metaGrid.DefaultCellStyle.SelectionForeColor = Color.White;

                metaGrid.Columns.Add("Property", "Forensic Property");
                metaGrid.Columns.Add("BaselineValue", "Baseline Manifest Value");
                metaGrid.Columns.Add("CurrentValue", "Current Disk Value");
                metaGrid.Columns.Add("Delta", "Variance / Assessment");

                metaGrid.Columns["Property"].FillWeight = 24;
                metaGrid.Columns["BaselineValue"].FillWeight = 26;
                metaGrid.Columns["CurrentValue"].FillWeight = 26;
                metaGrid.Columns["Delta"].FillWeight = 24;

                string fileTypeDesc = isOfficeDoc ? "Microsoft Office OpenXML (.docx)" : (isBinary ? "Binary / Non-Text Archive" : "Text Document");
                metaGrid.Rows.Add("File Format", fileTypeDesc, fileTypeDesc, "Detected Container");
                metaGrid.Rows.Add("File Size", $"{binaryReport.OldSize:N0} bytes", $"{binaryReport.NewSize:N0} bytes", $"{(binaryReport.SizeDelta >= 0 ? "+" : "")}{binaryReport.SizeDelta:N0} bytes");
                metaGrid.Rows.Add("Shannon Entropy", $"{binaryReport.OldEntropy:F2} / 8.0", $"{binaryReport.NewEntropy:F2} / 8.0", $"{(binaryReport.EntropyDelta >= 0 ? "+" : "")}{binaryReport.EntropyDelta:F2}");
                metaGrid.Rows.Add("Timestomp Anomaly", "Normal", binaryReport.TimestompingDetected ? "DETECTED (Rolled back)" : "None", binaryReport.TimestompingDetected ? "HIGH RISK" : "Normal");

                bool hashMatch = string.Equals(oldSha, newSha, StringComparison.OrdinalIgnoreCase);
                metaGrid.Rows.Add("SHA-256 Cryptographic Match", hashMatch ? "MATCH" : "BASELINE RECORD", hashMatch ? "MATCH" : "MODIFIED RECORD", hashMatch ? "🟢 Unchanged" : "🟡 Hash Variance Detected");

                var pnlGridWrapper = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 14, 0, 10) };
                pnlGridWrapper.Controls.Add(metaGrid);

                var lblFootnote = new Label
                {
                    Dock = DockStyle.Bottom,
                    Height = 36,
                    Text = "ℹ️ Shannon Entropy measures information density (0.0 to 8.0). High values (>7.5) indicate compression or encryption. Office OpenXML files are internally compressed ZIP packages.",
                    Font = new Font("Segoe UI", 8.5F),
                    ForeColor = Color.FromArgb(148, 163, 184)
                };

                pnlMeta.Controls.Add(pnlGridWrapper);
                pnlMeta.Controls.Add(lblFootnote);
                pnlMeta.Controls.Add(pnlCard);
                _tabBinary.Controls.Add(pnlMeta);
                _tabs.TabPages.Add(_tabBinary);
            }

            // AUTO TAB SELECTION: If no text diff is available, automatically focus Tab 2 so the user immediately sees the assessment!
            if (!hasTextDiff && _tabBinary != null)
            {
                _tabs.SelectedTab = _tabBinary;
            }

            // 3. Bottom Footer Panel
            var footer = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 52,
                BackColor = Color.FromArgb(15, 23, 42),
                Padding = new Padding(16, 10, 16, 10)
            };

            var btnClose = new Button
            {
                Text = "✕ Close",
                Width = 95,
                Height = 32,
                Dock = DockStyle.Right,
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F)
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => Close();

            var pnlSpacer = new Panel { Dock = DockStyle.Right, Width = 10, BackColor = Color.Transparent };

            var btnCopy = new Button
            {
                Text = "📋 Copy Forensic Report",
                Width = 170,
                Height = 32,
                Dock = DockStyle.Right,
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F)
            };
            btnCopy.FlatAppearance.BorderSize = 0;
            btnCopy.Click += (s, e) =>
            {
                string report = GenerateFullClipboardReport(relativePath, oldSha, newSha, binaryReport, diffReport, isOfficeDoc);
                Clipboard.SetText(report);
                MessageBox.Show("Forensic inspection report copied to clipboard!", "Copied", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            var pnlSpacer2 = new Panel { Dock = DockStyle.Right, Width = 10, BackColor = Color.Transparent };

            var btnSwitchTab = new Button
            {
                Text = "📊 Switch to Forensic Metadata",
                Width = 220,
                Height = 32,
                Dock = DockStyle.Right,
                BackColor = Color.FromArgb(79, 70, 229),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F),
                Visible = _tabBinary != null
            };
            btnSwitchTab.FlatAppearance.BorderSize = 0;
            btnSwitchTab.Click += (s, e) =>
            {
                if (_tabs.SelectedTab == _tabText && _tabBinary != null)
                {
                    _tabs.SelectedTab = _tabBinary;
                    btnSwitchTab.Text = "📄 Switch to Content View";
                }
                else
                {
                    _tabs.SelectedTab = _tabText;
                    btnSwitchTab.Text = "📊 Switch to Forensic Metadata";
                }
            };

            _tabs.SelectedIndexChanged += (s, e) =>
            {
                if (_tabs.SelectedTab == _tabText)
                    btnSwitchTab.Text = "📊 Switch to Forensic Metadata";
                else
                    btnSwitchTab.Text = "📄 Switch to Content View";
            };

            footer.Controls.Add(btnSwitchTab);
            footer.Controls.Add(pnlSpacer2);
            footer.Controls.Add(btnCopy);
            footer.Controls.Add(pnlSpacer);
            footer.Controls.Add(btnClose);

            Controls.Add(_tabs);
            Controls.Add(header);
            Controls.Add(footer);
        }

        private static void RenderDiff(RichTextBox rtb, DiffReport report)
        {
            rtb.SelectionColor = Color.FromArgb(147, 197, 253);
            rtb.AppendText($"// FORENSIC DIFF SUMMARY: +{report.AddedCount} added, -{report.DeletedCount} deleted, {report.UnchangedCount} unchanged\n");
            rtb.AppendText("// -----------------------------------------------------------------------------------------\n");

            if (report.AddedCount == 0 && report.DeletedCount == 0 && report.Lines.Count > 0)
            {
                rtb.SelectionColor = Color.Gold;
                rtb.AppendText("// Note: Visible lines match baseline. Cryptographic hash variance is due to line-endings (CRLF vs LF), trailing spaces, or encoding.\n\n");
            }
            else
            {
                rtb.AppendText("\n");
            }

            foreach (var line in report.Lines)
            {
                if (line.Type == DiffType.Added)
                {
                    rtb.SelectionColor = Color.LimeGreen;
                    rtb.AppendText($"[+] Line {line.NewLineNumber,3}:  {line.Text}\n");
                }
                else if (line.Type == DiffType.Deleted)
                {
                    rtb.SelectionColor = Color.FromArgb(255, 100, 100);
                    rtb.AppendText($"[-] Line {line.OldLineNumber,3}:  {line.Text}\n");
                }
                else
                {
                    rtb.SelectionColor = Color.LightGray;
                    rtb.AppendText($"    Line {line.NewLineNumber,3}:  {line.Text}\n");
                }
            }
        }

        private static void RenderNonTextExplanation(
            RichTextBox rtb,
            string relativePath,
            string oldSha,
            string newSha,
            BinaryDeltaReport binaryReport,
            bool isOfficeDoc,
            bool isBinary,
            string currentTextContent)
        {
            rtb.Clear();

            if (isOfficeDoc)
            {
                rtb.SelectionColor = Color.FromArgb(125, 211, 252);
                rtb.AppendText("═════════════════════════════════════════════════════════════════════════════════════════════\n");
                rtb.AppendText("  📦 MICROSOFT OFFICE OPENXML CONTAINER (.docx) — CRYPTOGRAPHIC VARIANCE ANALYSIS\n");
                rtb.AppendText("═════════════════════════════════════════════════════════════════════════════════════════════\n\n");

                rtb.SelectionColor = Color.Gold;
                rtb.AppendText("• Why did the cryptographic SHA-256 hash change when you saved the document?\n");
                rtb.SelectionColor = Color.FromArgb(226, 232, 240);
                rtb.AppendText(
                    "  Microsoft Word (.docx) files are not flat text files — they are compressed ZIP packages\n" +
                    "  containing XML markup (word/document.xml, docProps/core.xml, etc.).\n" +
                    "  Every time you click 'Save' in Microsoft Word, Word updates internal revision timestamps,\n" +
                    "  relationship IDs, and re-compresses package streams. This intentionally changes\n" +
                    "  the entire file's SHA-256 hash.\n\n");

                rtb.SelectionColor = Color.Gold;
                rtb.AppendText("• Cryptographic Integrity Metrics:\n");
                rtb.SelectionColor = Color.FromArgb(147, 197, 253);
                rtb.AppendText($"  - Baseline Manifest SHA-256 : {oldSha}\n");
                rtb.AppendText($"  - Current Disk File SHA-256 : {newSha}\n");
                if (binaryReport != null)
                {
                    rtb.AppendText($"  - File Size Variance        : {(binaryReport.SizeDelta >= 0 ? "+" : "")}{binaryReport.SizeDelta:N0} bytes ({binaryReport.OldSize:N0} -> {binaryReport.NewSize:N0} bytes)\n");
                    rtb.AppendText($"  - Shannon Entropy Density   : {binaryReport.OldEntropy:F2} -> {binaryReport.NewEntropy:F2} / 8.0\n");
                }
                rtb.AppendText("\n");

                rtb.SelectionColor = Color.FromArgb(134, 239, 172);
                rtb.AppendText("• Next Step:\n");
                rtb.SelectionColor = Color.FromArgb(226, 232, 240);
                rtb.AppendText(
                    "  1. Inspect the 'Forensic Metadata & Heuristics' tab above for file variance and timestomp checks.\n" +
                    "  2. In the Sentinel main dashboard, click 'Accept & Update Baseline' to seal your edits into the manifest.\n" +
                    "     Future scans will then automatically compute word-level diffs from your updated snapshot.\n\n");

                if (!string.IsNullOrEmpty(currentTextContent))
                {
                    string[] lines = currentTextContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                    rtb.SelectionColor = Color.FromArgb(192, 132, 252);
                    rtb.AppendText($"─────────────────────────────────────────────────────────────────────────────────────────────\n");
                    rtb.AppendText($"  📄 Extracted Word Document Content Snapshot ({lines.Length:N0} paragraphs extracted)\n");
                    rtb.AppendText($"─────────────────────────────────────────────────────────────────────────────────────────────\n");
                    rtb.SelectionColor = Color.LightGray;

                    int previewCount = Math.Min(lines.Length, 40);
                    for (int i = 0; i < previewCount; i++)
                    {
                        rtb.AppendText($"  [{i + 1,3}]  {lines[i]}\n");
                    }
                    if (lines.Length > previewCount)
                    {
                        rtb.SelectionColor = Color.LightSkyBlue;
                        rtb.AppendText($"\n  ... and {lines.Length - previewCount:N0} more paragraphs.\n");
                    }
                }
            }
            else
            {
                rtb.SelectionColor = Color.Orange;
                rtb.AppendText("// BINARY OR UNTRACKED FILE INSPECTION\n\n");
                rtb.SelectionColor = Color.LightGray;
                rtb.AppendText("• If this file was newly added, click 'Accept & Update Baseline' to record its initial state.\n");
                rtb.AppendText("• For compiled binaries, archives, and images, inspect the 'Forensic Metadata & Heuristics' tab above.\n\n");

                if (binaryReport != null)
                {
                    rtb.SelectionColor = Color.LightSkyBlue;
                    rtb.AppendText($"Baseline SHA-256 : {oldSha}\n");
                    rtb.AppendText($"Current  SHA-256 : {newSha}\n");
                    rtb.AppendText($"Size Variance    : {(binaryReport.SizeDelta >= 0 ? "+" : "")}{binaryReport.SizeDelta:N0} bytes\n");
                    rtb.AppendText($"Shannon Entropy  : {binaryReport.OldEntropy:F2} -> {binaryReport.NewEntropy:F2} / 8.0\n");
                }
            }
        }

        private static string GenerateFullClipboardReport(
            string relativePath,
            string oldSha,
            string newSha,
            BinaryDeltaReport binaryReport,
            DiffReport diffReport,
            bool isOfficeDoc)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("================================================================================");
            sb.AppendLine($"HASHCHECK SENTINEL — FORENSIC DIFF & HEURISTIC REPORT");
            sb.AppendLine($"File: {relativePath}");
            sb.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("================================================================================");
            sb.AppendLine($"Baseline SHA-256 : {oldSha}");
            sb.AppendLine($"Current  SHA-256 : {newSha}");

            if (binaryReport != null)
            {
                sb.AppendLine($"Size Baseline    : {binaryReport.OldSize:N0} bytes");
                sb.AppendLine($"Size Current     : {binaryReport.NewSize:N0} bytes (Delta: {(binaryReport.SizeDelta >= 0 ? "+" : "")}{binaryReport.SizeDelta:N0} bytes)");
                sb.AppendLine($"Entropy Baseline : {binaryReport.OldEntropy:F2} / 8.0");
                sb.AppendLine($"Entropy Current  : {binaryReport.NewEntropy:F2} / 8.0 (Delta: {(binaryReport.EntropyDelta >= 0 ? "+" : "")}{binaryReport.EntropyDelta:F2})");
                sb.AppendLine($"Timestomping     : {(binaryReport.TimestompingDetected ? "DETECTED" : "None")}");
                sb.AppendLine($"Assessment       : {binaryReport.Assessment}");
            }

            if (diffReport != null && diffReport.Lines.Count > 0)
            {
                sb.AppendLine("--------------------------------------------------------------------------------");
                sb.AppendLine($"CONTENT DIFF: +{diffReport.AddedCount} added, -{diffReport.DeletedCount} deleted, {diffReport.UnchangedCount} unchanged");
                sb.AppendLine("--------------------------------------------------------------------------------");
                foreach (var line in diffReport.Lines)
                {
                    if (line.Type == DiffType.Added) sb.AppendLine($"[+] Line {line.NewLineNumber,3}: {line.Text}");
                    else if (line.Type == DiffType.Deleted) sb.AppendLine($"[-] Line {line.OldLineNumber,3}: {line.Text}");
                }
            }

            return sb.ToString();
        }
    }
}
