using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using HashCheckSentinel.Core;
using HashCheckSentinel.UI;

namespace HashCheckSentinel
{
    public sealed class MainForm : Form
    {
        // UI Controls
        private readonly TextBox _txtFolder = new TextBox();
        private readonly Label _lblSystemStatus = new Label();
        private readonly Label _lblStatusDetail = new Label();
        private readonly Label _lblMerkle = new Label();
        private readonly Label _lblStorage = new Label();
        private readonly ProgressBar _progressBar = new ProgressBar();

        // Metric Counter Cards (Interactive Filters)
        private Label _cardAll;
        private Label _cardUnchanged;
        private Label _cardModified;
        private Label _cardAdded;
        private Label _cardDeleted;
        private Label _cardThreats;
        private string _activeFilter = "All"; // "All", "Unchanged", "Modified", "Added", "Deleted", "Threats"

        // Grid & Live Search
        private readonly DataGridView _grid = new DataGridView();
        private readonly TextBox _txtSearch = new TextBox();
        private readonly Label _lblFilterCount = new Label();
        private readonly ContextMenuStrip _gridContextMenu = new ContextMenuStrip();
        private readonly ToolTip _tooltips = new ToolTip();

        // Examiner Panel
        private readonly Panel _panelExaminer = new Panel();

        // Toolbar Buttons
        private Button _btnWatch;
        private Button _btnScan;
        private Button _btnBaseline;
        private Button _btnUpdateBaseline;
        private Button _btnAddFile;

        // Core State
        private BaselinePackage _activeBaseline;
        private string _baselineRootFolder;
        private List<FileScanResult> _currentScanResults = new List<FileScanResult>();
        private readonly LiveWatcher _liveWatcher = new LiveWatcher();
        private CancellationTokenSource _scanCts;
        private readonly System.Windows.Forms.Timer _liveDebounceTimer = new System.Windows.Forms.Timer();
        private volatile bool _isScanning = false;
        private volatile bool _pendingRescan = false;
        private readonly Font _threatFont = new Font("Segoe UI", 9F, FontStyle.Bold);

        public MainForm()
        {
            InitializeComponent();

            // Enable DoubleBuffering on DataGridView via reflection to eliminate flicker and stutter
            try
            {
                typeof(DataGridView).InvokeMember("DoubleBuffered",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.SetProperty,
                    null, _grid, new object[] { true });
            }
            catch { }

            // Configure debounced live watcher timer
            _liveDebounceTimer.Interval = 500;
            _liveDebounceTimer.Tick += (s, e) =>
            {
                _liveDebounceTimer.Stop();
                if (_isScanning)
                {
                    _pendingRescan = true;
                }
                else
                {
                    RunScan(true);
                }
            };

            _liveWatcher.FileActivityDetected += OnLiveFileActivity;
            _txtFolder.TextChanged += (s, e) => OnFolderInputChanged();
            this.Shown += (s, e) => ResetColumnLayout();
            this.ResizeEnd += (s, e) => { if (_grid.Columns["Status"] != null && _grid.Columns["Status"].Width < 90) ResetColumnLayout(); };

            // Enable Drag-and-Drop for any folder or file across the entire system
            AllowDrop = true;
            _txtFolder.AllowDrop = true;
            _grid.AllowDrop = true;

            DragEventHandler onDragEnter = (s, e) =>
            {
                if (e.Data.GetDataPresent(DataFormats.FileDrop))
                    e.Effect = DragDropEffects.Copy;
                else
                    e.Effect = DragDropEffects.None;
            };

            DragEventHandler onDragDrop = (s, e) =>
            {
                if (e.Data.GetDataPresent(DataFormats.FileDrop))
                {
                    var dropped = (string[])e.Data.GetData(DataFormats.FileDrop);
                    if (dropped != null && dropped.Length > 0)
                    {
                        HandleDroppedItems(dropped);
                    }
                }
            };

            DragEnter += onDragEnter;
            DragDrop += onDragDrop;
            _txtFolder.DragEnter += onDragEnter;
            _txtFolder.DragDrop += onDragDrop;
            _grid.DragEnter += onDragEnter;
            _grid.DragDrop += onDragDrop;

            // Intelligent directory initialization:
            // Check if user previously targeted a folder, or if Desktop\pbl exists, otherwise Examiner Demo Lab
            string initialTarget = null;
            try
            {
                string lastTargetFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "last_target.txt");
                if (File.Exists(lastTargetFile))
                {
                    string saved = File.ReadAllText(lastTargetFile, Encoding.UTF8).Trim();
                    if (Directory.Exists(saved)) initialTarget = saved;
                }
            }
            catch { }

            if (string.IsNullOrEmpty(initialTarget))
            {
                string desktopPbl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "pbl");
                if (Directory.Exists(desktopPbl))
                {
                    initialTarget = desktopPbl;
                }
                else
                {
                    initialTarget = DemoLab.GetDemoLabDirectory();
                }
            }

            _txtFolder.Text = initialTarget;
            if (string.Equals(initialTarget, DemoLab.GetDemoLabDirectory(), StringComparison.OrdinalIgnoreCase))
            {
                try { DemoLab.ResetLabToCleanState(); } catch { }
            }
            UpdateStorageLabel();
        }

        private void InitializeComponent()
        {
            Text = "HashCheck-Sentinel — Autonomous File Integrity & Forensic System";
            Width = 1260;
            Height = 760;
            MinimumSize = new Size(1020, 620);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(18, 30, 48);
            ForeColor = Color.White;

            // 1. TOP HEADER PANEL
            var pnlTop = new Panel
            {
                Dock = DockStyle.Top,
                Height = 104,
                BackColor = Color.FromArgb(11, 19, 32),
                Padding = new Padding(20, 10, 20, 8)
            };

            var lblLogo = new Label
            {
                Text = "🛡️ SentinelFIM",
                Font = new Font("Segoe UI", 16F, FontStyle.Bold),
                ForeColor = Color.FromArgb(96, 165, 250),
                AutoSize = true,
                Left = 20,
                Top = 8
            };

            var lblSub = new Label
            {
                Text = "Host-Based File Integrity Monitoring & Autonomous Ransomware Forensics",
                Font = new Font("Segoe UI", 8.5F),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Left = 22,
                Top = 38
            };

            _lblSystemStatus.Text = "● STANDBY: READY TO SCAN";
            _lblSystemStatus.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            _lblSystemStatus.ForeColor = Color.Gold;
            _lblSystemStatus.BackColor = Color.FromArgb(20, 32, 50);
            _lblSystemStatus.BorderStyle = BorderStyle.FixedSingle;
            _lblSystemStatus.Padding = new Padding(8, 4, 8, 4);
            _lblSystemStatus.AutoSize = true;
            _lblSystemStatus.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _lblSystemStatus.Left = pnlTop.Width - 360;
            _lblSystemStatus.Top = 14;

            // Folder Selection Row
            var pnlFolderRow = new Panel
            {
                Left = 22,
                Top = 64,
                Height = 32,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            pnlFolderRow.Width = Width - 64;

            var btnBrowse = CreateButton("📂 Browse Target ▾", 0, 0, (s, e) => ShowBrowseTargetMenu(s as Control), Color.FromArgb(37, 99, 235));
            btnBrowse.Dock = DockStyle.Right;
            btnBrowse.Width = 150;
            btnBrowse.Height = 30;

            var pnlSpacer = new Panel { Dock = DockStyle.Right, Width = 8, BackColor = Color.Transparent };

            var btnClearPath = CreateButton("✕ Clear", 0, 0, (s, e) => ClearSelectedTarget(), Color.FromArgb(71, 85, 105));
            btnClearPath.Dock = DockStyle.Right;
            btnClearPath.Width = 80;
            btnClearPath.Height = 30;
            _tooltips.SetToolTip(btnClearPath, "Deselect / clear the currently chosen folder or file and reset view");

            var pnlSpacer2 = new Panel { Dock = DockStyle.Right, Width = 8, BackColor = Color.Transparent };

            _txtFolder.Dock = DockStyle.Fill;
            _txtFolder.Font = new Font("Segoe UI", 10F);
            _txtFolder.BackColor = Color.FromArgb(30, 41, 59);
            _txtFolder.ForeColor = Color.White;
            _txtFolder.DoubleClick += (s, e) => BrowseFolder();

            pnlFolderRow.Controls.Add(btnBrowse);
            pnlFolderRow.Controls.Add(pnlSpacer);
            pnlFolderRow.Controls.Add(btnClearPath);
            pnlFolderRow.Controls.Add(pnlSpacer2);
            pnlFolderRow.Controls.Add(_txtFolder);
            btnBrowse.BringToFront();
            btnClearPath.BringToFront();

            pnlTop.Controls.AddRange(new Control[] { lblLogo, lblSub, _lblSystemStatus, pnlFolderRow });

            // 2. EXAMINER TEST LAB PANEL
            _panelExaminer.Dock = DockStyle.Top;
            _panelExaminer.Height = 46;
            _panelExaminer.BackColor = Color.FromArgb(30, 20, 48);
            _panelExaminer.Padding = new Padding(20, 8, 20, 8);
            _panelExaminer.Visible = true;

            var flowExaminer = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false
            };

            var lblLabTitle = new Label { Text = "🧪 Sandbox Lab:", AutoSize = true, ForeColor = Color.FromArgb(216, 180, 254), Font = new Font("Segoe UI", 9F, FontStyle.Bold), Padding = new Padding(0, 5, 6, 0) };
            var btnReset = CreateButton("🧹 Reset Clean Lab", 0, 0, (s, e) => RunDemoReset(), Color.FromArgb(88, 28, 135));
            var btnCase1 = CreateButton("1. Backdoor Injection", 0, 0, (s, e) => RunDemoCase1(), Color.FromArgb(180, 83, 9));
            var btnCase2 = CreateButton("2. AES Ransomware", 0, 0, (s, e) => RunDemoCase2(), Color.FromArgb(185, 28, 28));
            var btnCase3 = CreateButton("3. Baseline Tamper", 0, 0, (s, e) => RunDemoCase3(), Color.FromArgb(124, 45, 18));
            var btnCase4 = CreateButton("4. Stego Payload", 0, 0, (s, e) => RunDemoCase4(), Color.FromArgb(15, 118, 110));
            var btnOpenGuide = CreateButton("📖 Teacher Guide & Rubric", 0, 0, (s, e) => OpenTeacherGuide(), Color.FromArgb(109, 40, 217));

            _tooltips.SetToolTip(btnReset, "Reverts all Sandbox files to verified clean state and initializes baseline");
            _tooltips.SetToolTip(btnCase1, "Simulates malicious privilege escalation backdoor injected into server_config.py");
            _tooltips.SetToolTip(btnCase2, "Simulates high-entropy AES ransomware encryption outbreak on sensitive files");
            _tooltips.SetToolTip(btnCase3, "Simulates an adversary tampering directly with the baseline manifest in Notepad");
            _tooltips.SetToolTip(btnCase4, "Simulates stealth shellcode injected past PNG IEND image chunk");
            _tooltips.SetToolTip(btnOpenGuide, "Opens the interactive step-by-step teacher demonstration guide and evaluation rubric");

            flowExaminer.Controls.AddRange(new Control[] { lblLabTitle, btnReset, btnCase1, btnCase2, btnCase3, btnCase4, btnOpenGuide });
            _panelExaminer.Controls.Add(flowExaminer);

            // 3. METRIC CARDS ROW (6 Interactive Dashboard KPI Cards)
            var pnlCards = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 66,
                BackColor = Color.FromArgb(15, 23, 42),
                Padding = new Padding(20, 5, 20, 5),
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false
            };

            _cardAll = CreateCardButton("All", "📁 ALL FILES\n0", Color.FromArgb(37, 99, 235));
            _cardUnchanged = CreateCardButton("Unchanged", "🟢 CLEAN\n0", Color.FromArgb(16, 185, 129));
            _cardModified = CreateCardButton("Modified", "🟡 MODIFIED\n0", Color.FromArgb(245, 158, 11));
            _cardAdded = CreateCardButton("Added", "🔵 ADDED\n0", Color.FromArgb(14, 165, 233));
            _cardDeleted = CreateCardButton("Deleted", "⚪ DELETED\n0", Color.FromArgb(100, 116, 139));
            _cardThreats = CreateCardButton("Threats", "🔴 THREATS\n0", Color.FromArgb(239, 68, 68));

            pnlCards.Controls.AddRange(new Control[] { _cardAll, _cardUnchanged, _cardModified, _cardAdded, _cardDeleted, _cardThreats });

            // 4. CLEAN ACTION TOOLBAR (Streamlined, Zero Clutter)
            var pnlToolbar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 46,
                BackColor = Color.FromArgb(11, 18, 30),
                Padding = new Padding(20, 7, 20, 7),
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                AutoScroll = true
            };

            _btnScan = CreateButton("⚡ Multi-Core Scan", 0, 0, (s, e) => OnScanButtonClicked(), Color.FromArgb(16, 185, 129));
            _btnBaseline = CreateButton("🔒 Create Baseline", 0, 0, (s, e) => CreateBaseline(), Color.FromArgb(37, 99, 235));
            _btnAddFile = CreateButton("➕ Add File / Folder ▾", 0, 0, (s, e) => ShowAddMenu(_btnAddFile), Color.FromArgb(2, 132, 199));
            _btnUpdateBaseline = CreateButton("📥 Save Added Files to Baseline", 0, 0, (s, e) => AcceptAndUpdateBaseline(), Color.FromArgb(13, 148, 136));
            _btnWatch = CreateButton("👁️ Live Watch: OFF", 0, 0, (s, e) => ToggleLiveWatch(), Color.FromArgb(71, 85, 105));
            var btnReport = CreateButton("📑 Export Audit Report", 0, 0, (s, e) => ExportHtmlReport(), Color.FromArgb(79, 70, 229));
            var btnTeacherDemo = CreateButton("🎓 Teacher & Examiner Demo", 0, 0, (s, e) => OpenTeacherGuide(), Color.FromArgb(124, 58, 237));
            var btnTheory = CreateButton("ℹ️ Architecture & Theory", 0, 0, (s, e) => new TheoryDialog().ShowDialog(this), Color.FromArgb(51, 65, 85));

            _tooltips.SetToolTip(_btnScan, "Run parallel cryptographic hash & entropy scan across all CPU cores [F5]");
            _tooltips.SetToolTip(_btnBaseline, "Generate initial baseline and seal with Merkle Tree & HMAC-SHA256 signature");
            _tooltips.SetToolTip(_btnAddFile, "Import an entire folder, select multiple files, or create a new test file into the monitored directory");
            _tooltips.SetToolTip(_btnUpdateBaseline, "Accept newly added or modified files into the permanent baseline [Ctrl+S]");
            _tooltips.SetToolTip(_btnWatch, "Toggle continuous real-time filesystem monitoring via Windows Kernel I/O events");
            _tooltips.SetToolTip(btnReport, "Generate comprehensive executive HTML forensic audit report [Ctrl+R]");
            _tooltips.SetToolTip(btnTeacherDemo, "Open interactive evaluation guide and test suite for professors and examiners");
            _tooltips.SetToolTip(btnTheory, "View mathematical entropy formulas, RFC 2104 proofs, and viva defense reference [F1]");

            pnlToolbar.Controls.AddRange(new Control[] { _btnScan, _btnBaseline, _btnAddFile, _btnUpdateBaseline, _btnWatch, btnReport, btnTeacherDemo, btnTheory });

            // 5. LIVE SEARCH & FILTER BAR
            var pnlSearch = new Panel
            {
                Dock = DockStyle.Top,
                Height = 38,
                BackColor = Color.FromArgb(18, 30, 48),
                Padding = new Padding(20, 5, 20, 5)
            };

            var lblSearchIcon = new Label
            {
                Text = "🔍 Search:",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.Gainsboro,
                AutoSize = true,
                Left = 20,
                Top = 9
            };

            _txtSearch.SetBounds(95, 6, 360, 24);
            _txtSearch.Font = new Font("Segoe UI", 9.5F);
            _txtSearch.BackColor = Color.FromArgb(28, 44, 68);
            _txtSearch.ForeColor = Color.White;
            _txtSearch.TextChanged += (s, e) => RefreshGridAndMetrics();

            var btnClearSearch = CreateButton("✕ Clear", 465, 5, (s, e) => _txtSearch.Clear(), Color.FromArgb(50, 65, 85));
            btnClearSearch.Height = 26;
            btnClearSearch.Font = new Font("Segoe UI", 8.5F);

            _lblFilterCount.Text = "All files visible";
            _lblFilterCount.Font = new Font("Segoe UI", 8.5F);
            _lblFilterCount.ForeColor = Color.LightSteelBlue;
            _lblFilterCount.AutoSize = true;
            _lblFilterCount.Left = 545;
            _lblFilterCount.Top = 10;

            var btnAutoFitCols = CreateButton("📐 Auto-Fit Columns", 0, 0, (s, e) => ResetColumnLayout(), Color.FromArgb(51, 65, 85));
            btnAutoFitCols.Dock = DockStyle.Right;
            btnAutoFitCols.Width = 145;
            btnAutoFitCols.Height = 26;
            btnAutoFitCols.Font = new Font("Segoe UI", 8.5F);
            _tooltips.SetToolTip(btnAutoFitCols, "Automatically balances and fills all table columns to fit the window. (You can also drag column borders manually anytime)");

            pnlSearch.Controls.AddRange(new Control[] { lblSearchIcon, _txtSearch, btnClearSearch, _lblFilterCount, btnAutoFitCols });

            // 6. MAIN GRID
            _grid.Dock = DockStyle.Fill;
            _grid.BackgroundColor = Color.FromArgb(16, 26, 42);
            _grid.ForeColor = Color.White;
            _grid.Font = new Font("Segoe UI", 9F);
            _grid.ReadOnly = true;
            _grid.AllowUserToAddRows = false;
            _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _grid.RowHeadersVisible = false;
            _grid.EnableHeadersVisualStyles = false;
            _grid.BorderStyle = BorderStyle.None;
            _grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            _grid.GridColor = Color.FromArgb(28, 42, 64);
            _grid.ColumnHeadersHeight = 32;
            _grid.RowTemplate.Height = 28;
            _grid.AllowUserToResizeColumns = true;
            _grid.AllowUserToOrderColumns = true;

            _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(22, 34, 52);
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(180, 205, 235);
            _grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9F, FontStyle.Bold);

            _grid.DefaultCellStyle.BackColor = Color.FromArgb(16, 26, 40);
            _grid.DefaultCellStyle.ForeColor = Color.White;
            _grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(38, 70, 110);
            _grid.DefaultCellStyle.SelectionForeColor = Color.White;

            _grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(20, 32, 48);
            _grid.AlternatingRowsDefaultCellStyle.ForeColor = Color.White;
            _grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = Color.FromArgb(38, 70, 110);
            _grid.AlternatingRowsDefaultCellStyle.SelectionForeColor = Color.White;

            _grid.Columns.Add("Status", "Integrity Status");
            _grid.Columns["Status"].MinimumWidth = 130;
            _grid.Columns["Status"].FillWeight = 14;

            _grid.Columns.Add("Path", "Relative File Path");
            _grid.Columns["Path"].MinimumWidth = 260;
            _grid.Columns["Path"].FillWeight = 32;

            _grid.Columns.Add("Entropy", "Shannon Entropy");
            _grid.Columns["Entropy"].MinimumWidth = 110;
            _grid.Columns["Entropy"].FillWeight = 12;

            _grid.Columns.Add("Size", "Size");
            _grid.Columns["Size"].MinimumWidth = 90;
            _grid.Columns["Size"].FillWeight = 10;

            _grid.Columns.Add("Sha256", "SHA-256 Hash");
            _grid.Columns["Sha256"].MinimumWidth = 170;
            _grid.Columns["Sha256"].FillWeight = 18;

            _grid.Columns.Add("Forensics", "Forensic Action");
            _grid.Columns["Forensics"].MinimumWidth = 140;
            _grid.Columns["Forensics"].FillWeight = 14;

            _grid.CellDoubleClick += (s, e) =>
            {
                if (e.RowIndex >= 0) OpenDiffForSelectedRow(e.RowIndex);
            };
            _grid.CellClick += (s, e) =>
            {
                if (e.RowIndex >= 0 && e.ColumnIndex == _grid.Columns["Forensics"].Index)
                {
                    OpenDiffForSelectedRow(e.RowIndex);
                }
            };

            // Grid Context Menu
            _gridContextMenu.BackColor = Color.FromArgb(24, 36, 56);
            _gridContextMenu.ForeColor = Color.White;
            _gridContextMenu.Font = new Font("Segoe UI", 9F);

            var miDiff = new ToolStripMenuItem("🔍 Inspect Content / Forensic Diff (Enter)", null, (s, e) =>
            {
                if (_grid.CurrentRow != null && _grid.CurrentRow.Index >= 0)
                    OpenDiffForSelectedRow(_grid.CurrentRow.Index);
            });
            var miExplorer = new ToolStripMenuItem("📁 Show in Windows Explorer", null, (s, e) => ShowSelectedFileInExplorer());
            var miCopyRel = new ToolStripMenuItem("📋 Copy Relative Path", null, (s, e) => CopySelectedPath(false));
            var miCopyFull = new ToolStripMenuItem("📋 Copy Full Path", null, (s, e) => CopySelectedPath(true));
            var miCopyHash = new ToolStripMenuItem("📋 Copy SHA-256 Hash", null, (s, e) => CopySelectedHash());
            var miAcceptSingle = new ToolStripMenuItem("🔄 Accept This File into Baseline", null, (s, e) => AcceptSelectedFileChange());
            var miAutoFitColsMenu = new ToolStripMenuItem("📐 Auto-Fit / Reset Column Alignment", null, (s, e) => ResetColumnLayout());
            var miRemoveFromView = new ToolStripMenuItem("🚫 Remove from Current Scan List", null, (s, e) => RemoveSelectedFileFromScanList());
            var miDeleteFile = new ToolStripMenuItem("🗑️ Delete File from Disk (Abort / Remove)", null, (s, e) => DeleteSelectedFileFromDisk());

            _gridContextMenu.Items.AddRange(new ToolStripItem[] {
                miDiff,
                new ToolStripSeparator(),
                miAutoFitColsMenu,
                new ToolStripSeparator(),
                miExplorer,
                miCopyRel,
                miCopyFull,
                miCopyHash,
                new ToolStripSeparator(),
                miAcceptSingle,
                new ToolStripSeparator(),
                miRemoveFromView,
                miDeleteFile
            });

            _grid.ContextMenuStrip = _gridContextMenu;

            // 7. BOTTOM STATUS STRIP
            var pnlBottom = new Panel { Dock = DockStyle.Bottom, Height = 44, BackColor = Color.FromArgb(10, 18, 30), Padding = new Padding(20, 8, 20, 8) };

            _lblStatusDetail.Text = "Ready.";
            _lblStatusDetail.ForeColor = Color.Gainsboro;
            _lblStatusDetail.Font = new Font("Segoe UI", 8.5F);
            _lblStatusDetail.SetBounds(20, 12, 400, 20);

            _progressBar.SetBounds(430, 14, 200, 16);
            _progressBar.Visible = false;

            _lblMerkle.Text = "Merkle Root: [No Baseline Loaded]";
            _lblMerkle.ForeColor = Color.LightSkyBlue;
            _lblMerkle.Font = new Font("Consolas", 8F);
            _lblMerkle.SetBounds(650, 12, 340, 20);
            _lblMerkle.Anchor = AnchorStyles.Top | AnchorStyles.Right;

            _lblStorage.Text = "Cache: 0 KB";
            _lblStorage.ForeColor = Color.LightGray;
            _lblStorage.Font = new Font("Segoe UI", 8.5F);
            _lblStorage.SetBounds(1000, 12, 150, 20);
            _lblStorage.Anchor = AnchorStyles.Top | AnchorStyles.Right;

            pnlBottom.Controls.AddRange(new Control[] { _lblStatusDetail, _progressBar, _lblMerkle, _lblStorage });

            // ADD TO MAIN FORM
            Controls.Add(_grid);
            Controls.Add(pnlSearch);
            Controls.Add(pnlToolbar);
            Controls.Add(pnlCards);
            Controls.Add(_panelExaminer);
            Controls.Add(pnlTop);
            Controls.Add(pnlBottom);
        }

        private Label CreateCardButton(string filterName, string title, Color accentColor)
        {
            var lbl = new Label
            {
                Text = title,
                Width = 190,
                Height = 56,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.White,
                BackColor = Color.FromArgb(20, 32, 50),
                TextAlign = ContentAlignment.MiddleCenter,
                Margin = new Padding(0, 0, 8, 0),
                BorderStyle = BorderStyle.FixedSingle,
                Cursor = Cursors.Hand
            };

            lbl.Click += (s, e) => SetFilter(filterName);

            lbl.MouseEnter += (s, e) =>
            {
                if (_activeFilter != filterName)
                {
                    lbl.BackColor = Color.FromArgb(30, 48, 76);
                }
            };

            lbl.MouseLeave += (s, e) =>
            {
                if (_activeFilter != filterName)
                {
                    lbl.BackColor = Color.FromArgb(20, 32, 50);
                }
            };

            _tooltips.SetToolTip(lbl, $"Click to filter grid to '{filterName}' files only");
            return lbl;
        }

        private void UpdateCardVisuals()
        {
            if (_cardAll == null) return;

            _cardAll.BackColor = _activeFilter == "All" ? Color.FromArgb(37, 99, 235) : Color.FromArgb(20, 32, 50);
            _cardUnchanged.BackColor = _activeFilter == "Unchanged" ? Color.FromArgb(16, 110, 60) : Color.FromArgb(20, 32, 50);
            _cardModified.BackColor = _activeFilter == "Modified" ? Color.FromArgb(140, 100, 10) : Color.FromArgb(20, 32, 50);
            _cardAdded.BackColor = _activeFilter == "Added" ? Color.FromArgb(2, 132, 199) : Color.FromArgb(20, 32, 50);
            _cardDeleted.BackColor = _activeFilter == "Deleted" ? Color.FromArgb(71, 85, 105) : Color.FromArgb(20, 32, 50);
            _cardThreats.BackColor = _activeFilter == "Threats" ? Color.FromArgb(185, 28, 28) : Color.FromArgb(20, 32, 50);

            _cardAll.ForeColor = _activeFilter == "All" ? Color.White : Color.FromArgb(147, 197, 253);
            _cardUnchanged.ForeColor = _activeFilter == "Unchanged" ? Color.White : Color.FromArgb(52, 211, 153);
            _cardModified.ForeColor = _activeFilter == "Modified" ? Color.White : Color.FromArgb(251, 191, 36);
            _cardAdded.ForeColor = _activeFilter == "Added" ? Color.White : Color.FromArgb(56, 189, 248);
            _cardDeleted.ForeColor = _activeFilter == "Deleted" ? Color.White : Color.FromArgb(148, 163, 184);
            _cardThreats.ForeColor = _activeFilter == "Threats" ? Color.White : Color.FromArgb(248, 113, 113);
        }

        private void OpenTeacherGuide()
        {
            var dlg = new TeacherDemoDialog(
                () => RunDemoReset(),
                () => RunDemoCase1(),
                () => RunDemoCase2(),
                () => RunDemoCase3(),
                () => RunDemoCase4()
            );
            dlg.ShowDialog(this);
        }

        private static Button CreateButton(string text, int left, int top, EventHandler onClick, Color? bg = null)
        {
            var btn = new Button
            {
                Text = text,
                Left = left,
                Top = top,
                Height = 30,
                AutoSize = true,
                FlatStyle = FlatStyle.Flat,
                BackColor = bg ?? Color.FromArgb(41, 128, 185),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Cursor = Cursors.Hand,
                UseMnemonic = false,
                Margin = new Padding(0, 0, 8, 0)
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.Click += onClick;
            return btn;
        }

        private static string ResolveTargetDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            string trimmed = path.Trim().Trim('"', '\'');
            try
            {
                if (Directory.Exists(trimmed)) return trimmed;
                if (File.Exists(trimmed)) return Path.GetDirectoryName(trimmed);

                string parent = Path.GetDirectoryName(trimmed);
                if (!string.IsNullOrEmpty(parent) && Directory.Exists(parent)) return parent;
            }
            catch { }
            return null;
        }

        private void OnFolderInputChanged()
        {
            string root = ResolveTargetDirectory(_txtFolder.Text);
            bool isValidDir = !string.IsNullOrEmpty(root) && Directory.Exists(root);

            if (_btnBaseline != null) _btnBaseline.Enabled = isValidDir;
            if (_btnScan != null) _btnScan.Enabled = isValidDir;
            if (_btnUpdateBaseline != null) _btnUpdateBaseline.Enabled = isValidDir;

            if (isValidDir)
            {
                _activeBaseline = BaselineManager.FindInheritedOrLocalBaseline(root, out _baselineRootFolder);
                UpdateBaselineStatusUI();

                string demoDir = DemoLab.GetDemoLabDirectory();
                bool isDemoLab = string.Equals(root, demoDir, StringComparison.OrdinalIgnoreCase);
                if (_panelExaminer != null)
                {
                    _panelExaminer.Visible = isDemoLab;
                }

                // If Live Watch is active, immediately rebind it to the newly selected target folder!
                if (_liveWatcher != null && _liveWatcher.IsRunning)
                {
                    _liveWatcher.Start(root);
                    _lblStatusDetail.Text = $"👁️ Live Watch active: monitoring {Path.GetFileName(root)} ({DateTime.Now:HH:mm:ss})";
                }

                // Persist this target folder across application launches
                try
                {
                    string lastTargetFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "last_target.txt");
                    File.WriteAllText(lastTargetFile, root, Encoding.UTF8);
                }
                catch { }
            }
            else
            {
                if (_liveWatcher != null && _liveWatcher.IsRunning)
                {
                    _liveWatcher.Stop();
                }
                _activeBaseline = null;
                _baselineRootFolder = null;
                _lblSystemStatus.Text = "● STANDBY: SELECT DIRECTORY";
                _lblSystemStatus.ForeColor = Color.Gold;
                _lblMerkle.Text = "Merkle Root: [None]";
                _lblStorage.Text = "Cache: 0 KB";
            }
        }

        private void ShowBrowseTargetMenu(Control anchor)
        {
            var menu = new ContextMenuStrip();
            menu.BackColor = Color.FromArgb(24, 34, 52);
            menu.ForeColor = Color.White;
            menu.Font = new Font("Segoe UI", 9.5F);
            menu.ShowImageMargin = false;

            var itmFolder = new ToolStripMenuItem("  📁  Browse for Monitored Folder...  ", null, (s, e) => BrowseFolder());
            var itmFile = new ToolStripMenuItem("  📄  Browse for Specific File...  ", null, (s, e) => BrowseFile());
            var itmDemo = new ToolStripMenuItem("  🧪  Switch to Examiner Demo Lab  ", null, (s, e) =>
            {
                _txtFolder.Text = DemoLab.GetDemoLabDirectory();
                RunScan();
            });

            menu.Items.Add(itmFolder);
            menu.Items.Add(itmFile);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(itmDemo);

            if (anchor != null)
                menu.Show(anchor, new Point(0, anchor.Height));
            else
                menu.Show(Cursor.Position);
        }

        private void BrowseFolder()
        {
            using (var dlg = new FolderBrowserDialog { Description = "Select root directory to monitor", SelectedPath = ResolveTargetDirectory(_txtFolder.Text) ?? _txtFolder.Text })
            {
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _txtFolder.Text = dlg.SelectedPath;
                    RunScan();
                }
            }
        }

        private void BrowseFile()
        {
            using (var dlg = new OpenFileDialog { Title = "Select a file to monitor its folder and inspect", Filter = "All Files (*.*)|*.*" })
            {
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    string dir = Path.GetDirectoryName(dlg.FileName);
                    _txtFolder.Text = dir;
                    _txtSearch.Text = Path.GetFileName(dlg.FileName);
                    RunScan();
                }
            }
        }

        private void ShowAddMenu(Control anchor)
        {
            var menu = new ContextMenuStrip();
            menu.BackColor = Color.FromArgb(24, 34, 52);
            menu.ForeColor = Color.White;
            menu.Font = new Font("Segoe UI", 9.5F);
            menu.ShowImageMargin = false;

            var itmFolder = new ToolStripMenuItem("  📁  Import Entire Folder into Monitored Directory...  ", null, (s, e) => ImportEntireFolder());
            var itmFiles = new ToolStripMenuItem("  📄  Import Existing File(s)...  ", null, (s, e) => ImportExistingFiles());
            var itmNew = new ToolStripMenuItem("  📝  Create New Test File (e.g. hi.txt)...  ", null, (s, e) => CreateNewTextFilePrompt());
            var itmChange = new ToolStripMenuItem("  🎯  Change Active Monitored Folder...  ", null, (s, e) => BrowseFolder());

            menu.Items.Add(itmFolder);
            menu.Items.Add(itmFiles);
            menu.Items.Add(itmNew);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(itmChange);

            if (anchor != null)
                menu.Show(anchor, new Point(0, anchor.Height));
            else
                menu.Show(Cursor.Position);
        }

        private void ImportEntireFolder()
        {
            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
            {
                MessageBox.Show("Please choose a valid monitored folder first.", "Folder Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using (var dlg = new FolderBrowserDialog { Description = "Select an entire folder to import/copy into the monitored directory" })
            {
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    string sourceDir = dlg.SelectedPath;
                    if (string.Equals(sourceDir, root, StringComparison.OrdinalIgnoreCase))
                    {
                        MessageBox.Show("The selected folder is already the monitored root directory.", "Notice", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        return;
                    }

                    string folderName = Path.GetFileName(sourceDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                    if (string.IsNullOrEmpty(folderName)) folderName = "ImportedFolder";
                    string destDir = Path.Combine(root, folderName);

                    try
                    {
                        SetBusyState(true, $"Copying folder '{folderName}' into monitored directory...");
                        CopyDirectoryRecursive(sourceDir, destDir);
                        SetFilter("Added");
                        RunScan();
                        MessageBox.Show(
                            $"Entire folder '{folderName}' was successfully imported into:\n{root}\n\n" +
                            "• Sentinel scanned and highlighted all new files under 'Added'!\n" +
                            "• Click 'Save Added Files to Baseline' to accept them into the baseline manifest.",
                            "Folder Imported & Scanned",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to import folder: {ex.Message}", "Import Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    finally
                    {
                        SetBusyState(false, "Standby: Ready");
                    }
                }
            }
        }

        private void ImportExistingFiles()
        {
            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
            {
                MessageBox.Show("Please choose a valid monitored folder first.", "Folder Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using (var dlg = new OpenFileDialog
            {
                Title = "Select file(s) to copy into monitored directory",
                Multiselect = true,
                Filter = "All Files (*.*)|*.*|Code & Scripts (*.py;*.cs;*.c;*.cpp;*.js)|*.py;*.cs;*.c;*.cpp;*.js|Text Documents (*.txt;*.md;*.log;*.json)|*.txt;*.md;*.log;*.json"
            })
            {
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    int copied = 0;
                    try
                    {
                        SetBusyState(true, "Importing selected files...");
                        foreach (string sourceFile in dlg.FileNames)
                        {
                            string destFile = Path.Combine(root, Path.GetFileName(sourceFile));
                            File.Copy(sourceFile, destFile, true);
                            copied++;
                        }

                        SetFilter("Added");
                        RunScan();
                        MessageBox.Show(
                            $"{copied} file(s) copied into:\n{root}\n\n" +
                            "• Sentinel scanned and flagged them in the 'Added' section!\n" +
                            "• Click 'Save Added Files to Baseline' to accept them into the baseline manifest.",
                            "Files Imported & Scanned",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to copy files: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    finally
                    {
                        SetBusyState(false, "Standby: Ready");
                    }
                }
            }
        }

        private void CreateNewTextFilePrompt()
        {
            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
            {
                MessageBox.Show("Please choose a valid monitored folder first.", "Folder Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string fileName = PromptInput("Enter file name to create in directory (e.g. hi.txt):", "Create New Test File", "hi.txt");
            if (string.IsNullOrWhiteSpace(fileName)) return;

            string targetPath = Path.Combine(root, fileName.Trim());
            if (File.Exists(targetPath))
            {
                var overwrite = MessageBox.Show($"File '{fileName}' already exists in this folder. Overwrite it?", "File Exists", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (overwrite != DialogResult.Yes) return;
            }

            try
            {
                string dir = Path.GetDirectoryName(targetPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

                File.WriteAllText(targetPath, $"Sentinel FIM Test File created on {DateTime.Now:yyyy-MM-dd HH:mm:ss}\nInitial baseline line for {fileName}\n", Encoding.UTF8);

                SetFilter("Added");
                RunScan();
                MessageBox.Show(
                    $"File '{fileName}' was successfully created in:\n{root}\n\n" +
                    "1. Sentinel has scanned and marked it in the 'Added' section.\n" +
                    "2. To save this file into the baseline, click 'Save Added Files to Baseline'.\n" +
                    "3. After saving to baseline, making any future edits to this file will flag it as 'Modified'!",
                    "File Added to Directory",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to create file: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void CopyDirectoryRecursive(string sourceDir, string targetDir)
        {
            if (!Directory.Exists(targetDir))
            {
                Directory.CreateDirectory(targetDir);
            }

            foreach (string file in Directory.GetFiles(sourceDir))
            {
                try
                {
                    string dest = Path.Combine(targetDir, Path.GetFileName(file));
                    File.Copy(file, dest, true);
                }
                catch { }
            }

            foreach (string subDir in Directory.GetDirectories(sourceDir))
            {
                try
                {
                    string dest = Path.Combine(targetDir, Path.GetFileName(subDir));
                    CopyDirectoryRecursive(subDir, dest);
                }
                catch { }
            }
        }

        private void HandleDroppedItems(string[] dropped)
        {
            if (dropped == null || dropped.Length == 0) return;

            string currentRoot = ResolveTargetDirectory(_txtFolder.Text);

            if (dropped.Length == 1 && Directory.Exists(dropped[0]))
            {
                string droppedFolder = dropped[0];
                var res = MessageBox.Show(
                    $"You dropped folder:\n{droppedFolder}\n\n" +
                    "• Click [YES] to SET this folder as the Active Monitored Directory and Scan it.\n" +
                    "• Click [NO] to COPY / IMPORT this entire folder into the current directory.\n" +
                    "• Click [CANCEL] to abort.",
                    "Folder Dropped into Sentinel",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Question);

                if (res == DialogResult.Yes)
                {
                    _txtFolder.Text = droppedFolder;
                    RunScan();
                }
                else if (res == DialogResult.No)
                {
                    if (string.IsNullOrEmpty(currentRoot) || !Directory.Exists(currentRoot))
                    {
                        MessageBox.Show("Please choose a valid monitored folder first.", "Folder Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                    string folderName = Path.GetFileName(droppedFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                    if (string.IsNullOrEmpty(folderName)) folderName = "ImportedFolder";
                    string targetDir = Path.Combine(currentRoot, folderName);
                    try
                    {
                        SetBusyState(true, $"Importing folder '{folderName}'...");
                        CopyDirectoryRecursive(droppedFolder, targetDir);
                        SetFilter("Added");
                        RunScan();
                        MessageBox.Show($"Entire folder '{folderName}' was imported into:\n{currentRoot}\n\nAll files have been scanned and flagged under 'Added'!\nClick 'Save Added Files to Baseline' to accept them.", "Folder Imported", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to import folder: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    finally
                    {
                        SetBusyState(false, "Standby: Ready");
                    }
                }
                return;
            }

            if (dropped.Length == 1 && File.Exists(dropped[0]))
            {
                string droppedFile = dropped[0];
                string parentDir = Path.GetDirectoryName(droppedFile);

                var askTarget = MessageBox.Show(
                    $"You dropped file:\n{Path.GetFileName(droppedFile)}\n\n" +
                    $"• Click [YES] to SET its containing folder as the Active Monitored Directory and Scan it:\n  {parentDir}\n\n" +
                    $"• Click [NO] to COPY / IMPORT this file into the current monitored directory:\n  {currentRoot}\n\n" +
                    "• Click [CANCEL] to abort.",
                    "File Dropped into Sentinel",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Question);

                if (askTarget == DialogResult.Yes)
                {
                    _txtFolder.Text = parentDir;
                    _txtSearch.Clear();
                    RunScan();
                    return;
                }
                else if (askTarget == DialogResult.Cancel)
                {
                    return;
                }
            }

            var choice = MessageBox.Show(
                $"You dropped {dropped.Length} item(s) onto Sentinel.\n\n" +
                $"Do you want to copy/import them into the active monitored directory?\n\nTarget Folder: {currentRoot}",
                "Import Dropped Items",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (choice == DialogResult.Yes)
            {
                if (string.IsNullOrEmpty(currentRoot) || !Directory.Exists(currentRoot))
                {
                    MessageBox.Show("Please choose a valid monitored folder first.", "Folder Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                try
                {
                    SetBusyState(true, "Importing dropped items...");
                    int count = 0;
                    foreach (var item in dropped)
                    {
                        if (Directory.Exists(item))
                        {
                            string fName = Path.GetFileName(item.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                            if (string.IsNullOrEmpty(fName)) fName = "ImportedFolder";
                            CopyDirectoryRecursive(item, Path.Combine(currentRoot, fName));
                            count++;
                        }
                        else if (File.Exists(item))
                        {
                            string fName = Path.GetFileName(item);
                            File.Copy(item, Path.Combine(currentRoot, fName), true);
                            count++;
                        }
                    }
                    SetFilter("Added");
                    RunScan();
                    MessageBox.Show($"{count} item(s) successfully imported into:\n{currentRoot}\n\nScanned and highlighted under 'Added'!\nClick 'Save Added Files to Baseline' to seal them.", "Import Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error importing items: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally
                {
                    SetBusyState(false, "Standby: Ready");
                }
            }
        }

        private static string PromptInput(string prompt, string title, string defaultValue = "")
        {
            using (var form = new Form
            {
                Width = 440,
                Height = 170,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                Text = title,
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(16, 26, 42),
                ForeColor = Color.White,
                MaximizeBox = false,
                MinimizeBox = false
            })
            {
                var lbl = new Label { Left = 20, Top = 16, Text = prompt, AutoSize = true, Font = new Font("Segoe UI", 9.5F) };
                var txt = new TextBox { Left = 20, Top = 46, Width = 380, Text = defaultValue, Font = new Font("Segoe UI", 10F), BackColor = Color.FromArgb(28, 44, 68), ForeColor = Color.White };
                var btnOk = new Button { Text = "Create", Left = 210, Width = 90, Top = 86, Height = 28, DialogResult = DialogResult.OK, BackColor = Color.FromArgb(37, 99, 235), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
                var btnCancel = new Button { Text = "Cancel", Left = 310, Width = 90, Top = 86, Height = 28, DialogResult = DialogResult.Cancel, BackColor = Color.FromArgb(51, 65, 85), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };

                form.Controls.AddRange(new Control[] { lbl, txt, btnOk, btnCancel });
                form.AcceptButton = btnOk;
                form.CancelButton = btnCancel;

                return form.ShowDialog() == DialogResult.OK ? txt.Text.Trim() : null;
            }
        }

        private void CreateBaseline()
        {
            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
            {
                MessageBox.Show("Please choose a valid existing folder.", "Folder Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            SetBusyState(true, "Scanning directory and generating cryptographic baseline...");

            ThreadPool.QueueUserWorkItem(state =>
            {
                try
                {
                    var scanResults = Hasher.ScanDirectoryParallel(root, UpdateProgress);
                    var package = BaselineManager.SaveBaseline(root, scanResults);

                    BeginInvoke((MethodInvoker)delegate
                    {
                        _activeBaseline = package;
                        _baselineRootFolder = root;
                        _currentScanResults = scanResults;
                        foreach (var r in _currentScanResults) r.Status = "Unchanged";

                        UpdateBaselineStatusUI();
                        RefreshGridAndMetrics();
                        SetBusyState(false, "Baseline generated and cryptographically sealed.");

                        MessageBox.Show(
                            $"Cryptographic baseline successfully created and sealed with HMAC-SHA256!\n\n" +
                            $"• Monitored files: {_activeBaseline.Entries.Count}\n" +
                            $"• Merkle Root: {_activeBaseline.MerkleRoot.Substring(0, Math.Min(16, _activeBaseline.MerkleRoot.Length))}...\n\n" +
                            "All current files have been sealed as the initial trusted baseline (100% Clean).\n" +
                            "Any future edits made to these files will now be tracked and flagged under 'Modified'!",
                            "Baseline Sealed & Monitored",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    });
                }
                catch (Exception ex)
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        SetBusyState(false, "Error: " + ex.Message);
                        MessageBox.Show("Error generating baseline: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    });
                }
            });
        }

        private void AcceptAndUpdateBaseline()
        {
            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
            {
                MessageBox.Show("Please choose a valid existing folder first.", "Folder Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            int modified = 0, added = 0, deleted = 0, threats = 0;
            foreach (var r in _currentScanResults)
            {
                if (r.Status == "Modified") modified++;
                else if (r.Status == "Added") added++;
                else if (r.Status == "Deleted") deleted++;
                else if (r.Status.Contains("Threat") || !string.IsNullOrEmpty(r.ThreatReason)) threats++;
            }

            int pendingChanges = modified + added + deleted + threats;

            if (_currentScanResults == null || _currentScanResults.Count == 0)
            {
                var prompt = MessageBox.Show(
                    "No scan has been run yet for this directory.\n\nDo you want to run a multi-core scan now and seal the current state as baseline?",
                    "Initialize Baseline",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);

                if (prompt == DialogResult.Yes)
                {
                    CreateBaseline();
                }
                return;
            }

            if (pendingChanges == 0)
            {
                MessageBox.Show(
                    "There are no unaccepted changes. The baseline is already 100% up-to-date with the monitored directory.",
                    "Baseline Up to Date",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            var confirm = MessageBox.Show(
                $"Accept detected changes and update the baseline?\n\n" +
                $"• Added files: {added}\n" +
                $"• Modified files: {modified}\n" +
                $"• Deleted files: {deleted}\n" +
                $"• Threats / Alerts: {threats}\n\n" +
                "This action will:\n" +
                "1. Archive the previous baseline snapshot into history.\n" +
                "2. Save current files and line diff snapshots into the new baseline.\n" +
                "3. Compute a new Merkle Root & sign with HMAC-SHA256.\n" +
                "4. Reset system integrity status to Clean.",
                "Accept & Update Baseline",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (confirm != DialogResult.Yes) return;

            SetBusyState(true, "Updating and cryptographically re-sealing baseline...");

            ThreadPool.QueueUserWorkItem(state =>
            {
                try
                {
                    string targetFolder = !string.IsNullOrEmpty(_baselineRootFolder) && Directory.Exists(_baselineRootFolder)
                        ? _baselineRootFolder
                        : root;

                    var updatedFiles = new List<FileScanResult>();
                    foreach (var item in _currentScanResults)
                    {
                        if (item.Status == "Deleted") continue;
                        if (item.Status == "Unreadable" || item.Status == "Locked") continue;

                        if (string.IsNullOrEmpty(item.FullPath))
                        {
                            item.FullPath = Path.Combine(root, item.RelativePath);
                        }

                        if (!File.Exists(item.FullPath)) continue;

                        updatedFiles.Add(item);
                    }

                    var newPackage = BaselineManager.SaveBaseline(targetFolder, updatedFiles);

                    BeginInvoke((MethodInvoker)delegate
                    {
                        _activeBaseline = newPackage;
                        _baselineRootFolder = targetFolder;

                        foreach (var item in updatedFiles)
                        {
                            item.Status = "Unchanged";
                            item.ThreatReason = null;
                        }
                        _currentScanResults = updatedFiles;

                        UpdateBaselineStatusUI();
                        RefreshGridAndMetrics();
                        SetBusyState(false, "Baseline updated and cryptographically sealed.");

                        MessageBox.Show(
                            $"Baseline successfully updated and re-sealed!\n\n" +
                            $"• Monitored files: {_activeBaseline.Entries.Count}\n" +
                            $"• New Merkle Root: {_activeBaseline.MerkleRoot.Substring(0, Math.Min(16, _activeBaseline.MerkleRoot.Length))}...\n" +
                            $"• HMAC-SHA256 Signature: Verified\n\n" +
                            "All current files are now accepted into baseline. Future edits will be tracked as Modified.",
                            "Baseline Updated & Sealed",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    });
                }
                catch (Exception ex)
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        SetBusyState(false, "Error: " + ex.Message);
                        MessageBox.Show("Error updating baseline: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    });
                }
            });
        }

        private void OnScanButtonClicked()
        {
            if (_isScanning)
            {
                AbortCurrentScan();
            }
            else
            {
                // Clear any single-file search filter from previous file browsing
                // so the user sees all files and all detected changes in the folder
                if (_txtSearch != null && !string.IsNullOrWhiteSpace(_txtSearch.Text))
                {
                    _txtSearch.Clear();
                }
                RunScan(false);
            }
        }

        private void RunScan(bool isLiveWatchTrigger = false)
        {
            if (_isScanning)
            {
                _pendingRescan = true;
                return;
            }

            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
            {
                if (!isLiveWatchTrigger)
                {
                    MessageBox.Show("Select an existing folder first.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                return;
            }

            // Always reload the baseline from disk on manual scan to guarantee fresh comparison
            if (_activeBaseline == null || !isLiveWatchTrigger)
            {
                _activeBaseline = BaselineManager.FindInheritedOrLocalBaseline(root, out _baselineRootFolder);
            }

            if (_activeBaseline == null)
            {
                if (isLiveWatchTrigger)
                {
                    _lblSystemStatus.Text = "⚠️ UNMONITORED: CLICK 'CREATE BASELINE' TO INITIALIZE";
                    _lblSystemStatus.ForeColor = Color.Orange;
                    _lblStatusDetail.Text = "Live Watch detected file activity, but no baseline exists to compare against. Click 'Create Baseline'.";
                    return;
                }

                var ask = MessageBox.Show(
                    "No cryptographic baseline exists for this folder yet.\n\n" +
                    "To monitor file integrity, a baseline must first be created to record the initial trusted state.\n\n" +
                    "Would you like to scan this folder and create its cryptographic baseline now?",
                    "No Baseline Found — Initialize Now?",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);

                if (ask == DialogResult.Yes)
                {
                    CreateBaseline();
                }
                else
                {
                    _lblSystemStatus.Text = "⚠️ UNMONITORED: CLICK 'CREATE BASELINE' TO INITIALIZE";
                    _lblSystemStatus.ForeColor = Color.Orange;
                    _lblStatusDetail.Text = "Folder is unsealed. Please click 'Create Baseline' first.";
                }
                return;
            }

            // Verify Tamper Seal First!
            if (!_activeBaseline.IsSealValid)
            {
                _lblSystemStatus.Text = "🚨 CRITICAL: BASELINE INTEGRITY SEAL BROKEN!";
                _lblSystemStatus.ForeColor = Color.Red;
                MessageBox.Show("CRITICAL INTEGRITY ALARM!\n\nThe baseline file has been tampered with or modified without authorization.\nHMAC signature verification failed.", "Baseline Tampering Detected", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            _isScanning = true;
            if (_btnScan != null)
            {
                _btnScan.Text = "🛑 Abort Scan [Esc]";
                _btnScan.BackColor = Color.FromArgb(220, 38, 38);
                _btnScan.Enabled = true;
            }
            SetBusyState(true, "Running multi-core parallel integrity scan... [Press Esc or click Abort to cancel]");
            _scanCts = new CancellationTokenSource();

            ThreadPool.QueueUserWorkItem(state =>
            {
                try
                {
                    var currentFiles = Hasher.ScanDirectoryParallel(root, UpdateProgress, _scanCts.Token);
                    var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    foreach (var item in currentFiles)
                    {
                        // Normalize relative path if inherited from ancestor baseline
                        string baselineLookupKey = item.RelativePath;
                        if (!string.IsNullOrEmpty(_baselineRootFolder) && !string.Equals(_baselineRootFolder, root, StringComparison.OrdinalIgnoreCase))
                        {
                            if (item.FullPath.StartsWith(_baselineRootFolder, StringComparison.OrdinalIgnoreCase))
                            {
                                baselineLookupKey = item.FullPath.Substring(_baselineRootFolder.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                            }
                        }

                        seenPaths.Add(baselineLookupKey);
                        seenPaths.Add(item.RelativePath);

                        BaselineEntry baselineEntry = null;
                        if (!_activeBaseline.Entries.TryGetValue(baselineLookupKey, out baselineEntry))
                        {
                            if (!_activeBaseline.Entries.TryGetValue(item.RelativePath, out baselineEntry))
                            {
                                string slashKey = baselineLookupKey.Replace('\\', '/');
                                if (!_activeBaseline.Entries.TryGetValue(slashKey, out baselineEntry))
                                {
                                    string backslashKey = baselineLookupKey.Replace('/', '\\');
                                    _activeBaseline.Entries.TryGetValue(backslashKey, out baselineEntry);
                                }
                            }
                        }

                        if (item.Status == "Locked" || item.Status == "Unreadable")
                        {
                            // If file is locked (e.g. actively being saved by Word/Notepad):
                            // Check if file size or timestamp changed from baseline
                            if (baselineEntry != null)
                            {
                                if (item.FileSize != baselineEntry.FileSize || Math.Abs(item.LastModified.Ticks - baselineEntry.LastModifiedTicks) > TimeSpan.FromSeconds(2).Ticks)
                                {
                                    item.Status = "Modified";
                                    item.ThreatReason = "File modified (in-use / saving by editor)";
                                    if (string.IsNullOrEmpty(item.Sha256) || item.Sha256 == "—") item.Sha256 = "(Saving in progress...)";
                                }
                                else
                                {
                                    item.Status = "Unchanged";
                                }
                            }
                            else
                            {
                                item.Status = "Added";
                            }
                            continue;
                        }

                        if (baselineEntry != null)
                        {
                            if (string.Equals(item.Sha256, baselineEntry.Sha256, StringComparison.OrdinalIgnoreCase))
                            {
                                item.Status = "Unchanged";
                            }
                            else
                            {
                                // File Modified! Check if Ransomware/High-Entropy
                                if (item.Entropy >= 7.85 && baselineEntry.Entropy < 7.0)
                                {
                                    item.Status = "🚨 Threat: Encrypted";
                                    item.ThreatReason = $"Entropy jumped from {baselineEntry.Entropy:F2} to {item.Entropy:F2} (Probable Ransomware)";
                                }
                                else
                                {
                                    item.Status = "Modified";
                                }
                            }
                        }
                        else
                        {
                            item.Status = "Added";
                        }
                    }

                    // Check for Deleted files (only if they strictly belong inside the currently scanned root)
                    string safeRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

                    foreach (var entry in _activeBaseline.Entries.Values)
                    {
                        string effectiveRoot = !string.IsNullOrEmpty(_baselineRootFolder) ? _baselineRootFolder : root;
                        string fullEntryPath = Path.GetFullPath(Path.Combine(effectiveRoot, entry.RelativePath));

                        if (fullEntryPath.StartsWith(safeRoot, StringComparison.OrdinalIgnoreCase))
                        {
                            string relToScannedRoot = fullEntryPath.Substring(safeRoot.Length);
                            // Foolproof check: only mark as deleted if NOT seen in scan AND file actually does not exist on disk
                            if (!seenPaths.Contains(relToScannedRoot) && !seenPaths.Contains(entry.RelativePath) && !File.Exists(fullEntryPath))
                            {
                                currentFiles.Add(new FileScanResult
                                {
                                    RelativePath = relToScannedRoot,
                                    FullPath = fullEntryPath,
                                    Sha256 = entry.Sha256,
                                    Status = "Deleted",
                                    FileSize = entry.FileSize,
                                    Entropy = entry.Entropy,
                                    IsBinary = entry.IsBinary
                                });
                            }
                        }
                    }

                    BeginInvoke((MethodInvoker)delegate
                    {
                        _isScanning = false;
                        ResetScanButtonUI();
                        _currentScanResults = currentFiles;
                        RefreshGridAndMetrics();

                        if (_scanCts != null && _scanCts.IsCancellationRequested)
                        {
                            SetBusyState(false, "Scan aborted by user.");
                            _lblSystemStatus.Text = "⚠️ SCAN CANCELLED BY USER";
                            _lblSystemStatus.ForeColor = Color.Orange;
                            _lblStatusDetail.Text = "Scan operation was aborted. Displaying partial results.";
                        }
                        else
                        {
                            SetBusyState(false, "Scan complete.");

                            int modCount = 0;
                            int threatCount = 0;
                            int addedCount = 0;
                            int deletedCount = 0;
                            foreach (var r in _currentScanResults)
                            {
                                if (r.Status == "Modified") modCount++;
                                else if (r.Status.Contains("Threat") || !string.IsNullOrEmpty(r.ThreatReason)) threatCount++;
                                else if (r.Status == "Added") addedCount++;
                                else if (r.Status == "Deleted") deletedCount++;
                            }

                            if (isLiveWatchTrigger)
                            {
                                if (threatCount > 0)
                                {
                                    SetFilter("Threats");
                                    _lblStatusDetail.Text = $"🚨 Live Alert: {threatCount} threat(s) detected in real-time!";
                                }
                                else if (modCount > 0)
                                {
                                    SetFilter("Modified");
                                    _lblStatusDetail.Text = $"🟡 Live Watch: {modCount} file(s) modified! Auto-switched to Modified view.";
                                }
                                else if (addedCount > 0 && _activeFilter != "All")
                                {
                                    SetFilter("Added");
                                    _lblStatusDetail.Text = $"🔵 Live Watch: {addedCount} new file(s) added.";
                                }
                                else
                                {
                                    _lblStatusDetail.Text = $"🟢 Live Watch: Scanned at {DateTime.Now:HH:mm:ss}. System clean.";
                                }
                            }
                            else
                            {
                                int changes = modCount + addedCount + deletedCount + threatCount;
                                if (threatCount > 0)
                                {
                                    _lblSystemStatus.Text = $"🚨 SECURITY ALERT: {threatCount} THREAT(S) DETECTED";
                                    _lblSystemStatus.ForeColor = Color.Red;
                                    _lblStatusDetail.Text = $"Scan finished: {threatCount} threat(s), {modCount} modified, {addedCount} added, {deletedCount} deleted. Click KPI cards to inspect.";
                                    SetFilter("Threats");
                                }
                                else if (modCount > 0)
                                {
                                    _lblSystemStatus.Text = $"🟡 INTEGRITY DRIFT: {modCount} FILE(S) MODIFIED";
                                    _lblSystemStatus.ForeColor = Color.Gold;
                                    _lblStatusDetail.Text = $"Scan finished: {modCount} modified file(s) detected! Showing Modified files below.";
                                    SetFilter("Modified");
                                }
                                else if (changes > 0)
                                {
                                    _lblSystemStatus.Text = $"🔵 UNSEALED CHANGES: {addedCount} Added, {deletedCount} Deleted";
                                    _lblSystemStatus.ForeColor = Color.DeepSkyBlue;
                                    _lblStatusDetail.Text = $"Scan finished: {addedCount} added, {deletedCount} deleted. Click 'Save Added Files to Baseline' to seal.";
                                    SetFilter(addedCount > 0 ? "Added" : "All");
                                }
                                else
                                {
                                    _lblSystemStatus.Text = "🟢 INTEGRITY VERIFIED: 100% MATCH";
                                    _lblSystemStatus.ForeColor = Color.LimeGreen;
                                    _lblStatusDetail.Text = "Scan finished: All files match cryptographic baseline perfectly.";
                                    if (_activeFilter != "All") SetFilter("All");
                                }
                            }
                        }

                        if (_pendingRescan)
                        {
                            _pendingRescan = false;
                            _liveDebounceTimer.Start();
                        }
                    });
                }
                catch (Exception ex)
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        _isScanning = false;
                        ResetScanButtonUI();
                        if (_scanCts != null && _scanCts.IsCancellationRequested)
                        {
                            SetBusyState(false, "Scan aborted by user.");
                            _lblSystemStatus.Text = "⚠️ SCAN CANCELLED BY USER";
                            _lblSystemStatus.ForeColor = Color.Orange;
                            _lblStatusDetail.Text = "Scan operation was aborted.";
                        }
                        else
                        {
                            SetBusyState(false, "Error: " + ex.Message);
                            MessageBox.Show("Scan error: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    });
                }
            });
        }

        private void ToggleLiveWatch()
        {
            if (_liveWatcher.IsRunning)
            {
                _liveWatcher.Stop();
                _btnWatch.Text = "👁️ Live Watch: OFF";
                _btnWatch.BackColor = Color.FromArgb(71, 85, 105);
                _lblSystemStatus.Text = "● STANDBY: WATCHER PAUSED";
                _lblSystemStatus.ForeColor = Color.LightGray;
                _lblStatusDetail.Text = "Live watcher paused.";
            }
            else
            {
                string root = ResolveTargetDirectory(_txtFolder.Text);
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
                {
                    MessageBox.Show("Choose a valid monitored folder first.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (_activeBaseline == null)
                {
                    _activeBaseline = BaselineManager.FindInheritedOrLocalBaseline(root, out _baselineRootFolder);
                }

                _liveWatcher.Start(root);
                _btnWatch.Text = "👁️ Live Watch: ACTIVE";
                _btnWatch.BackColor = Color.FromArgb(16, 185, 129);
                _lblSystemStatus.Text = "🟢 LIVE WATCH ACTIVE: MONITORING 24/7";
                _lblSystemStatus.ForeColor = Color.LimeGreen;

                // Immediately run a scan so all current changes are surfaced without waiting
                RunScan(false);

                if (_activeBaseline == null)
                {
                    _lblStatusDetail.Text = "⚠️ Live Watch active, but no baseline is saved yet! Click 'Create Baseline' so edits can be detected as 'Modified'.";
                }
                else
                {
                    _lblStatusDetail.Text = $"Live Watch active: monitoring {Path.GetFileName(root)} ({_activeBaseline.Entries.Count} files in baseline). Watching for edits...";
                }
            }
        }

        private void OnLiveFileActivity(string fullPath, string changeType)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => OnLiveFileActivity(fullPath, changeType)));
                return;
            }

            _lblStatusDetail.Text = $"⚡ [Live Event] {changeType}: {Path.GetFileName(fullPath)} ({DateTime.Now:HH:mm:ss}) — auto-scanning...";

            _liveDebounceTimer.Stop();
            _liveDebounceTimer.Start();
        }

        private void RefreshGridAndMetrics()
        {
            int countUnchanged = 0, countModified = 0, countAdded = 0, countDeleted = 0, countThreats = 0;

            foreach (var item in _currentScanResults)
            {
                if (item.Status == "Unchanged") countUnchanged++;
                else if (item.Status == "Modified") countModified++;
                else if (item.Status == "Added") countAdded++;
                else if (item.Status == "Deleted") countDeleted++;
                else if (item.Status.Contains("Threat") || !string.IsNullOrEmpty(item.ThreatReason)) countThreats++;
            }

            int totalFiles = _currentScanResults.Count;
            if (_cardAll != null) _cardAll.Text = $"📁 ALL FILES\n{totalFiles:N0}";
            if (_cardUnchanged != null) _cardUnchanged.Text = $"🟢 CLEAN\n{countUnchanged:N0}";
            if (_cardModified != null) _cardModified.Text = $"🟡 MODIFIED\n{countModified:N0}";
            if (_cardAdded != null) _cardAdded.Text = $"🔵 ADDED\n{countAdded:N0}";
            if (_cardDeleted != null) _cardDeleted.Text = $"⚪ DELETED\n{countDeleted:N0}";
            if (_cardThreats != null) _cardThreats.Text = $"🔴 THREATS\n{countThreats:N0}";

            // Intelligent auto-fallback: if the current filter has 0 matching files, fall back to "All" so the table is never blank
            if (totalFiles > 0)
            {
                if (_activeFilter == "Modified" && countModified == 0) _activeFilter = "All";
                else if (_activeFilter == "Added" && countAdded == 0) _activeFilter = "All";
                else if (_activeFilter == "Deleted" && countDeleted == 0) _activeFilter = "All";
                else if (_activeFilter == "Threats" && countThreats == 0) _activeFilter = "All";
                else if (_activeFilter == "Unchanged" && countUnchanged == 0) _activeFilter = "All";
            }

            UpdateCardVisuals();

            int totalChanges = countModified + countAdded + countDeleted + countThreats;

            if (_btnUpdateBaseline != null)
            {
                if (totalChanges > 0)
                {
                    _btnUpdateBaseline.Text = $"🔄 Accept & Update Baseline ({totalChanges})";
                    _btnUpdateBaseline.BackColor = Color.FromArgb(0, 150, 136);
                }
                else
                {
                    _btnUpdateBaseline.Text = "🔄 Accept & Update Baseline";
                    _btnUpdateBaseline.BackColor = Color.FromArgb(45, 90, 85);
                }
            }

            if (countThreats > 0)
            {
                _lblSystemStatus.Text = $"🚨 ALARM: {countThreats} SECURITY THREAT(S) DETECTED!";
                _lblSystemStatus.ForeColor = Color.OrangeRed;
            }
            else if (countModified > 0)
            {
                _lblSystemStatus.Text = $"🟡 INTEGRITY WARNING: {countModified} FILE(S) MODIFIED";
                _lblSystemStatus.ForeColor = Color.Gold;
            }
            else if (countAdded > 0 || countDeleted > 0)
            {
                _lblSystemStatus.Text = $"🔵 UNSEALED CHANGES: {countAdded} Added, {countDeleted} Deleted (Click 'Accept & Update Baseline' to seal)";
                _lblSystemStatus.ForeColor = Color.DeepSkyBlue;
            }
            else
            {
                _lblSystemStatus.Text = "🟢 SYSTEM CLEAN: 100% INTEGRITY VERIFIED";
                _lblSystemStatus.ForeColor = Color.LimeGreen;
            }

            // High-speed batched grid population with DoubleBuffering and Cap
            _grid.SuspendLayout();
            _grid.Rows.Clear();

            const int MaxDisplayRows = 1000;
            var changeRows = new List<DataGridViewRow>();
            var unchangedRows = new List<DataGridViewRow>();
            int matchingCount = 0;
            int unchangedShown = 0;
            string searchTerm = _txtSearch != null ? _txtSearch.Text.Trim() : null;
            bool hasSearch = !string.IsNullOrEmpty(searchTerm);

            // Sort results so that changes (Threats, Modified, Added, Deleted) ALWAYS appear at the top!
            var sortedResults = new List<FileScanResult>(_currentScanResults);
            sortedResults.Sort((a, b) =>
            {
                int pA = GetStatusPriority(a.Status, a.ThreatReason);
                int pB = GetStatusPriority(b.Status, b.ThreatReason);
                if (pA != pB) return pA.CompareTo(pB);
                return string.Compare(a.RelativePath, b.RelativePath, StringComparison.OrdinalIgnoreCase);
            });

            foreach (var item in sortedResults)
            {
                bool show = false;
                if (_activeFilter == "All") show = true;
                else if (_activeFilter == "Changes" && item.Status != "Unchanged") show = true;
                else if (_activeFilter == "Unchanged" && item.Status == "Unchanged") show = true;
                else if (_activeFilter == "Modified" && item.Status == "Modified") show = true;
                else if (_activeFilter == "Added" && item.Status == "Added") show = true;
                else if (_activeFilter == "Deleted" && item.Status == "Deleted") show = true;
                else if (_activeFilter == "Threats" && (item.Status.Contains("Threat") || !string.IsNullOrEmpty(item.ThreatReason))) show = true;

                if (!show) continue;

                if (hasSearch)
                {
                    bool matchesSearch = (item.RelativePath != null && item.RelativePath.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0)
                                      || (item.Sha256 != null && item.Sha256.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0)
                                      || (item.Status != null && item.Status.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesSearch) continue;
                }

                matchingCount++;
                bool isChange = item.Status != "Unchanged";

                // Changes (Threats, Modified, Added, Deleted) are NEVER capped! They must ALWAYS be displayed!
                // Only Unchanged/Clean files are capped to MaxDisplayRows for maximum rendering performance.
                if (!isChange)
                {
                    unchangedShown++;
                    if (unchangedShown > MaxDisplayRows && (_activeFilter == "All" || _activeFilter == "Unchanged"))
                    {
                        continue;
                    }
                }

                var row = new DataGridViewRow();
                row.CreateCells(_grid,
                    item.Status,
                    item.RelativePath,
                    $"{item.Entropy:F2} / 8.0",
                    item.FileSize < 1024 ? $"{item.FileSize} B" : $"{item.FileSize / 1024.0:F1} KB",
                    item.Sha256.Length > 16 ? item.Sha256.Substring(0, 16) + "..." : item.Sha256,
                    item.Status == "Modified" || item.Status.Contains("Threat") ? "🔍 View Diff / Forensics" : "Details"
                );

                if (item.Status.Contains("Threat") || !string.IsNullOrEmpty(item.ThreatReason))
                {
                    row.Cells[0].Style.ForeColor = Color.OrangeRed;
                    row.Cells[0].Style.Font = _threatFont;
                }
                else if (item.Status == "Modified") row.Cells[0].Style.ForeColor = Color.Gold;
                else if (item.Status == "Added") row.Cells[0].Style.ForeColor = Color.DeepSkyBlue;
                else if (item.Status == "Deleted") row.Cells[0].Style.ForeColor = Color.DarkGray;
                else row.Cells[0].Style.ForeColor = Color.LimeGreen;

                if (isChange)
                    changeRows.Add(row);
                else
                    unchangedRows.Add(row);
            }

            var displayRows = new List<DataGridViewRow>();
            displayRows.AddRange(changeRows);
            displayRows.AddRange(unchangedRows);

            if (unchangedShown > MaxDisplayRows && (_activeFilter == "All" || _activeFilter == "Unchanged"))
            {
                var noticeRow = new DataGridViewRow();
                noticeRow.CreateCells(_grid,
                    "ℹ️ Notice",
                    $"Showing all changes + first {MaxDisplayRows:N0} of {unchangedShown:N0} clean files. Use filter buttons to view specific subsets.",
                    "—", "—", "—", "—"
                );
                noticeRow.Cells[0].Style.ForeColor = Color.LightSkyBlue;
                noticeRow.Cells[1].Style.ForeColor = Color.LightSkyBlue;
                displayRows.Add(noticeRow);
            }

            _grid.Rows.AddRange(displayRows.ToArray());
            _grid.ResumeLayout();

            // Self-healing check: if columns ever crushed below readability, restore optimal layout
            if (_grid.Columns["Status"] != null && _grid.Columns["Status"].Width < 90)
            {
                ResetColumnLayout();
            }

            if (_lblFilterCount != null)
            {
                if (hasSearch)
                    _lblFilterCount.Text = $"Showing {displayRows.Count:N0} of {matchingCount:N0} matching '{searchTerm}'";
                else if (matchingCount > displayRows.Count)
                    _lblFilterCount.Text = $"Showing {displayRows.Count:N0} of {matchingCount:N0} files (capped for performance)";
                else
                    _lblFilterCount.Text = $"Showing {displayRows.Count:N0} file(s)";
            }

            UpdateStorageLabel();
        }

        private static int GetStatusPriority(string status, string threatReason)
        {
            if (string.IsNullOrEmpty(status)) return 4;
            if (status.Contains("Threat") || !string.IsNullOrEmpty(threatReason)) return 0;
            if (status == "Modified") return 1;
            if (status == "Added") return 2;
            if (status == "Deleted") return 3;
            return 4; // Unchanged
        }

        private void SetFilter(string filter)
        {
            _activeFilter = filter;
            RefreshGridAndMetrics();
        }

        private void OpenDiffForSelectedRow(int rowIndex)
        {
            if (rowIndex < 0 || rowIndex >= _grid.Rows.Count) return;

            string relPath = _grid.Rows[rowIndex].Cells["Path"].Value != null ? _grid.Rows[rowIndex].Cells["Path"].Value.ToString() : null;
            if (relPath == null) return;

            var item = _currentScanResults.Find(r => r.RelativePath.Equals(relPath, StringComparison.OrdinalIgnoreCase));
            if (item == null) return;

            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root)) root = _txtFolder.Text;

            BaselineEntry oldEntry = null;
            if (_activeBaseline != null)
            {
                if (!_activeBaseline.Entries.TryGetValue(item.RelativePath, out oldEntry))
                {
                    if (!string.IsNullOrEmpty(_baselineRootFolder) && !string.IsNullOrEmpty(item.FullPath) && item.FullPath.StartsWith(_baselineRootFolder, StringComparison.OrdinalIgnoreCase))
                    {
                        string relToMaster = item.FullPath.Substring(_baselineRootFolder.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                        _activeBaseline.Entries.TryGetValue(relToMaster, out oldEntry);
                    }
                }
            }

            string baseFolder = !string.IsNullOrEmpty(_baselineRootFolder) && Directory.Exists(_baselineRootFolder) ? _baselineRootFolder : root;
            string oldText = BaselineManager.LoadCompressedSnapshotText(baseFolder, oldEntry != null ? oldEntry.RelativePath : item.RelativePath);
            if (oldText == null && !string.Equals(baseFolder, root, StringComparison.OrdinalIgnoreCase))
            {
                oldText = BaselineManager.LoadCompressedSnapshotText(root, item.RelativePath);
            }

            string newText = null;
            string currentPath = !string.IsNullOrEmpty(item.FullPath) ? item.FullPath : Path.Combine(root, item.RelativePath);
            bool isOfficeDoc = OfficeTextExtractor.IsOfficeDocument(item.RelativePath);

            if (File.Exists(currentPath))
            {
                if (!item.IsBinary && item.FileSize < 5 * 1024 * 1024)
                {
                    try { newText = File.ReadAllText(currentPath, Encoding.UTF8); } catch { }
                }
                else if (isOfficeDoc && item.FileSize < 25 * 1024 * 1024)
                {
                    newText = OfficeTextExtractor.ExtractText(currentPath);
                }
            }

            DiffReport diffReport = null;
            if (oldText != null && newText != null)
            {
                diffReport = DiffEngine.ComputeTextDiff(oldText, newText);
            }
            else if (oldText == null && newText != null && !item.IsBinary && !isOfficeDoc)
            {
                diffReport = new DiffReport();
                string[] lines = newText.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                for (int i = 0; i < lines.Length; i++)
                {
                    diffReport.Lines.Add(new DiffLine
                    {
                        Type = DiffType.Added,
                        NewLineNumber = i + 1,
                        Text = lines[i]
                    });
                    diffReport.AddedCount++;
                }
            }
            else if (oldText != null && newText == null)
            {
                diffReport = new DiffReport();
                string[] lines = oldText.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                for (int i = 0; i < lines.Length; i++)
                {
                    diffReport.Lines.Add(new DiffLine
                    {
                        Type = DiffType.Deleted,
                        OldLineNumber = i + 1,
                        Text = lines[i]
                    });
                    diffReport.DeletedCount++;
                }
            }

            BinaryDeltaReport binaryReport = DiffEngine.InspectBinaryDelta(item.RelativePath, oldEntry, item);

            var dlg = new DiffDialog(
                item.RelativePath,
                oldEntry != null ? oldEntry.Sha256 : "—",
                item.Sha256,
                diffReport,
                binaryReport,
                item.IsBinary,
                newText);
            dlg.ShowDialog(this);
        }

        private void ShowSelectedFileInExplorer()
        {
            if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0) return;
            string relPath = _grid.CurrentRow.Cells["Path"].Value != null ? _grid.CurrentRow.Cells["Path"].Value.ToString() : null;
            if (string.IsNullOrEmpty(relPath)) return;

            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root)) root = _txtFolder.Text;
            string fullPath = Path.Combine(root, relPath);

            try
            {
                if (File.Exists(fullPath))
                {
                    System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{fullPath}\"");
                }
                else if (Directory.Exists(root))
                {
                    System.Diagnostics.Process.Start("explorer.exe", $"\"{root}\"");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not launch Explorer: " + ex.Message, "Explorer Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void CopySelectedPath(bool fullPath)
        {
            if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0) return;
            string relPath = _grid.CurrentRow.Cells["Path"].Value != null ? _grid.CurrentRow.Cells["Path"].Value.ToString() : null;
            if (string.IsNullOrEmpty(relPath)) return;

            string textToCopy = relPath;
            if (fullPath)
            {
                string root = ResolveTargetDirectory(_txtFolder.Text);
                if (string.IsNullOrEmpty(root)) root = _txtFolder.Text;
                textToCopy = Path.Combine(root, relPath);
            }

            try
            {
                Clipboard.SetText(textToCopy);
                _lblStatusDetail.Text = $"Copied to clipboard: {textToCopy}";
            }
            catch { }
        }

        private void CopySelectedHash()
        {
            if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0) return;
            string relPath = _grid.CurrentRow.Cells["Path"].Value != null ? _grid.CurrentRow.Cells["Path"].Value.ToString() : null;
            if (string.IsNullOrEmpty(relPath)) return;

            var item = _currentScanResults.Find(r => r.RelativePath.Equals(relPath, StringComparison.OrdinalIgnoreCase));
            if (item != null && !string.IsNullOrEmpty(item.Sha256))
            {
                try
                {
                    Clipboard.SetText(item.Sha256);
                    _lblStatusDetail.Text = $"Copied SHA-256 to clipboard: {item.Sha256}";
                }
                catch { }
            }
        }

        private void AcceptSelectedFileChange()
        {
            if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0) return;
            string relPath = _grid.CurrentRow.Cells["Path"].Value != null ? _grid.CurrentRow.Cells["Path"].Value.ToString() : null;
            if (string.IsNullOrEmpty(relPath)) return;

            var item = _currentScanResults.Find(r => r.RelativePath.Equals(relPath, StringComparison.OrdinalIgnoreCase));
            if (item == null) return;

            if (item.Status == "Unchanged")
            {
                MessageBox.Show($"File '{relPath}' is already verified and unchanged in baseline.", "Already in Baseline", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var confirm = MessageBox.Show($"Accept current state of '{relPath}' into the baseline manifest?\n\nThis will atomically re-seal the Merkle Tree and HMAC-SHA256 signature.", "Accept Single File Change", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (confirm != DialogResult.Yes) return;

            try
            {
                string root = ResolveTargetDirectory(_txtFolder.Text);
                if (string.IsNullOrEmpty(root)) root = _txtFolder.Text;

                _activeBaseline = BaselineManager.AcceptSingleFile(root, item);
                _baselineRootFolder = root;
                UpdateBaselineStatusUI();
                RunScan();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to accept file change: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AbortCurrentScan()
        {
            if (_isScanning && _scanCts != null && !_scanCts.IsCancellationRequested)
            {
                try
                {
                    _scanCts.Cancel();
                    SetBusyState(true, "Stopping worker threads...");
                    _lblSystemStatus.Text = "🛑 ABORTING SCAN...";
                    _lblSystemStatus.ForeColor = Color.OrangeRed;
                    _lblStatusDetail.Text = "Scan abort requested. Halting parallel tasks...";
                }
                catch { }
            }
        }

        private void ResetScanButtonUI()
        {
            if (_btnScan != null)
            {
                _btnScan.Text = "⚡ Multi-Core Scan";
                _btnScan.BackColor = Color.FromArgb(16, 185, 129);
                _btnScan.Enabled = true;
            }
        }

        private void ClearSelectedTarget()
        {
            if (_isScanning)
            {
                AbortCurrentScan();
            }
            _txtFolder.Text = string.Empty;
            _activeBaseline = null;
            _baselineRootFolder = null;
            _currentScanResults.Clear();
            RefreshGridAndMetrics();
            _lblSystemStatus.Text = "● STANDBY: SELECT DIRECTORY";
            _lblSystemStatus.ForeColor = Color.Gold;
            _lblStatusDetail.Text = "Selection cleared. Select or drop a folder to begin.";
            _lblMerkle.Text = "Merkle Root: [None]";
            _lblStorage.Text = "Cache: 0 KB";
            if (_panelExaminer != null) _panelExaminer.Visible = false;
        }

        private void ResetColumnLayout()
        {
            if (_grid == null || _grid.Columns.Count == 0) return;

            try
            {
                _grid.SuspendLayout();
                _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;

                int availableWidth = _grid.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4;
                if (availableWidth < 700) availableWidth = 1180;

                int statusW = Math.Max(140, (int)(availableWidth * 0.13));
                int pathW = Math.Max(280, (int)(availableWidth * 0.33));
                int entropyW = Math.Max(110, (int)(availableWidth * 0.11));
                int sizeW = Math.Max(90, (int)(availableWidth * 0.09));
                int hashW = Math.Max(180, (int)(availableWidth * 0.19));
                int forensicW = Math.Max(135, availableWidth - (statusW + pathW + entropyW + sizeW + hashW));

                if (_grid.Columns["Status"] != null) { _grid.Columns["Status"].Width = statusW; _grid.Columns["Status"].MinimumWidth = 120; _grid.Columns["Status"].Resizable = DataGridViewTriState.True; }
                if (_grid.Columns["Path"] != null) { _grid.Columns["Path"].Width = pathW; _grid.Columns["Path"].MinimumWidth = 220; _grid.Columns["Path"].Resizable = DataGridViewTriState.True; }
                if (_grid.Columns["Entropy"] != null) { _grid.Columns["Entropy"].Width = entropyW; _grid.Columns["Entropy"].MinimumWidth = 100; _grid.Columns["Entropy"].Resizable = DataGridViewTriState.True; }
                if (_grid.Columns["Size"] != null) { _grid.Columns["Size"].Width = sizeW; _grid.Columns["Size"].MinimumWidth = 80; _grid.Columns["Size"].Resizable = DataGridViewTriState.True; }
                if (_grid.Columns["Sha256"] != null) { _grid.Columns["Sha256"].Width = hashW; _grid.Columns["Sha256"].MinimumWidth = 160; _grid.Columns["Sha256"].Resizable = DataGridViewTriState.True; }
                if (_grid.Columns["Forensics"] != null) { _grid.Columns["Forensics"].Width = forensicW; _grid.Columns["Forensics"].MinimumWidth = 130; _grid.Columns["Forensics"].Resizable = DataGridViewTriState.True; }

                _grid.ResumeLayout();
            }
            catch { }
        }

        private void DeleteSelectedFileFromDisk()
        {
            if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0) return;
            string relPath = _grid.CurrentRow.Cells["Path"].Value != null ? _grid.CurrentRow.Cells["Path"].Value.ToString() : null;
            if (string.IsNullOrEmpty(relPath)) return;

            string root = ResolveTargetDirectory(_txtFolder.Text);
            if (string.IsNullOrEmpty(root)) root = _txtFolder.Text;
            string fullPath = Path.Combine(root, relPath);

            var confirm = MessageBox.Show(
                $"Are you sure you want to permanently delete this file from disk?\n\nFile: {relPath}\nFull path: {fullPath}",
                "Confirm Delete File",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (confirm == DialogResult.Yes)
            {
                try
                {
                    if (File.Exists(fullPath))
                    {
                        File.Delete(fullPath);
                        _currentScanResults.RemoveAll(r => string.Equals(r.RelativePath, relPath, StringComparison.OrdinalIgnoreCase));
                        RefreshGridAndMetrics();
                        MessageBox.Show($"File '{relPath}' was successfully deleted.", "Deleted", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show("File does not exist on disk.", "Notice", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to delete file: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void RemoveSelectedFileFromScanList()
        {
            if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0) return;
            string relPath = _grid.CurrentRow.Cells["Path"].Value != null ? _grid.CurrentRow.Cells["Path"].Value.ToString() : null;
            if (string.IsNullOrEmpty(relPath)) return;

            _currentScanResults.RemoveAll(r => string.Equals(r.RelativePath, relPath, StringComparison.OrdinalIgnoreCase));
            RefreshGridAndMetrics();
            _lblStatusDetail.Text = $"Removed '{relPath}' from current results table.";
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == Keys.Escape && _isScanning)
            {
                AbortCurrentScan();
                return true;
            }
            if (keyData == Keys.F5)
            {
                RunScan();
                return true;
            }
            if (keyData == (Keys.Control | Keys.S))
            {
                AcceptAndUpdateBaseline();
                return true;
            }
            if (keyData == (Keys.Control | Keys.O))
            {
                BrowseFolder();
                return true;
            }
            if (keyData == (Keys.Control | Keys.F))
            {
                _txtSearch.Focus();
                _txtSearch.SelectAll();
                return true;
            }
            if (keyData == (Keys.Control | Keys.R))
            {
                ExportHtmlReport();
                return true;
            }
            if (keyData == Keys.F1)
            {
                new TheoryDialog().ShowDialog(this);
                return true;
            }
            if (keyData == Keys.Enter && _grid.Focused)
            {
                if (_grid.CurrentRow != null && _grid.CurrentRow.Index >= 0)
                {
                    OpenDiffForSelectedRow(_grid.CurrentRow.Index);
                    return true;
                }
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        private void UpdateBaselineStatusUI()
        {
            if (_activeBaseline != null)
            {
                string currentDir = ResolveTargetDirectory(_txtFolder.Text);
                bool isInherited = !string.IsNullOrEmpty(_baselineRootFolder) && !string.Equals(_baselineRootFolder, currentDir, StringComparison.OrdinalIgnoreCase);
                string shortMerkle = !string.IsNullOrEmpty(_activeBaseline.MerkleRoot) && _activeBaseline.MerkleRoot.Length > 20 ? _activeBaseline.MerkleRoot.Substring(0, 20) + "..." : (_activeBaseline.MerkleRoot ?? "—");

                if (isInherited)
                {
                    string parentName = Path.GetFileName(_baselineRootFolder);
                    _lblMerkle.Text = $"Merkle (Inherited: {parentName}): {shortMerkle}";
                    _lblSystemStatus.Text = $"🟢 INHERITED BASELINE ({parentName}): {(_activeBaseline.IsSealValid ? "VERIFIED" : "TAMPERED")}";
                }
                else
                {
                    _lblMerkle.Text = $"Merkle: {shortMerkle}";
                    _lblSystemStatus.Text = $"🟢 BASELINE LOADED: {(_activeBaseline.IsSealValid ? "VERIFIED" : "TAMPERED")}";
                }
                _lblMerkle.ForeColor = _activeBaseline.IsSealValid ? Color.LightGreen : Color.OrangeRed;
            }
            else
            {
                _lblMerkle.Text = "Merkle Root: [None]";
                _lblMerkle.ForeColor = Color.LightSkyBlue;
                _lblSystemStatus.Text = "⚠️ UNMONITORED: CLICK 'CREATE BASELINE' TO INITIALIZE";
                _lblSystemStatus.ForeColor = Color.Orange;
            }
            UpdateStorageLabel();
        }

        private void UpdateStorageLabel()
        {
            string root = ResolveTargetDirectory(_txtFolder.Text) ?? _txtFolder.Text;
            string usage = BaselineManager.GetTotalStorageUsageFormatted(root);
            _lblStorage.Text = $"Cache: {usage}";
        }

        private void PurgeBaselineCache()
        {
            string root = ResolveTargetDirectory(_txtFolder.Text) ?? _txtFolder.Text;
            var confirm = MessageBox.Show("Purge rolling history cache to reclaim disk space?", "Purge Cache", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (confirm == DialogResult.Yes)
            {
                BaselineManager.PurgeOldArchives(root);
                UpdateStorageLabel();
                MessageBox.Show("Cache purged successfully. Active baseline preserved.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private static string EscapeHtml(string s)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;");
        }

        private void ExportHtmlReport()
        {
            if (_currentScanResults == null || _currentScanResults.Count == 0)
            {
                MessageBox.Show("Run a scan first before generating an audit report.", "No Data", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                string root = ResolveTargetDirectory(_txtFolder.Text) ?? _txtFolder.Text;
                string reportPath = Path.Combine(root, $"FIM_Forensic_Audit_Report_{DateTime.UtcNow:yyyyMMdd_HHmmss}.html");

                int totalCount = _currentScanResults.Count;
                int unchanged = 0, modified = 0, added = 0, deleted = 0, threats = 0;
                foreach (var r in _currentScanResults)
                {
                    if (r.Status == "Unchanged") unchanged++;
                    else if (r.Status == "Modified") modified++;
                    else if (r.Status == "Added") added++;
                    else if (r.Status == "Deleted") deleted++;
                    else if (r.Status.Contains("Threat") || !string.IsNullOrEmpty(r.ThreatReason)) threats++;
                }

                var html = new StringBuilder();
                html.AppendLine("<!DOCTYPE html>");
                html.AppendLine("<html lang='en'>");
                html.AppendLine("<head>");
                html.AppendLine("<meta charset='utf-8'>");
                html.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
                html.AppendLine("<title>HashCheck-Sentinel — Cryptographic File Integrity & Forensic Audit Report</title>");
                html.AppendLine("<style>");
                html.AppendLine("  * { box-sizing: border-box; margin: 0; padding: 0; }");
                html.AppendLine("  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0c141f; color: #e2e8f0; line-height: 1.5; padding: 32px 24px; }");
                html.AppendLine("  .container { max-width: 1400px; margin: 0 auto; }");
                html.AppendLine("  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e2d3d; padding-bottom: 20px; margin-bottom: 24px; }");
                html.AppendLine("  .brand h1 { font-size: 24px; font-weight: 700; color: #60a5fa; display: flex; align-items: center; gap: 10px; }");
                html.AppendLine("  .brand p { font-size: 13px; color: #94a3b8; margin-top: 4px; }");
                html.AppendLine("  .meta { text-align: right; font-size: 13px; color: #94a3b8; }");
                html.AppendLine("  .meta b { color: #f1f5f9; }");
                html.AppendLine("  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }");
                html.AppendLine("  .card { background: #131f2e; border: 1px solid #1e3146; border-radius: 8px; padding: 16px; text-align: center; }");
                html.AppendLine("  .card-num { font-size: 26px; font-weight: 800; margin-bottom: 4px; }");
                html.AppendLine("  .card-label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8; }");
                html.AppendLine("  .c-clean { color: #34d399; } .c-mod { color: #fbbf24; } .c-add { color: #38bdf8; } .c-del { color: #94a3b8; } .c-threat { color: #f87171; }");
                html.AppendLine("  .crypto-box { background: #111b27; border: 1px solid #23374d; border-radius: 8px; padding: 18px; margin-bottom: 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; font-size: 13px; }");
                html.AppendLine("  .crypto-prop { color: #94a3b8; margin-bottom: 4px; font-weight: 600; }");
                html.AppendLine("  .crypto-val { font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; background: #0a111a; padding: 6px 10px; border-radius: 4px; border: 1px solid #1a2a3a; word-break: break-all; color: #93c5fd; }");
                html.AppendLine("  .seal-verified { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; background: rgba(52, 211, 153, 0.15); color: #34d399; border: 1px solid #34d399; font-size: 11px; }");
                html.AppendLine("  .seal-tampered { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; background: rgba(248, 113, 113, 0.15); color: #f87171; border: 1px solid #f87171; font-size: 11px; }");
                html.AppendLine("  .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px; }");
                html.AppendLine("  .filters { display: flex; gap: 8px; flex-wrap: wrap; }");
                html.AppendLine("  .btn-filter { background: #162436; border: 1px solid #243b56; color: #cbd5e1; padding: 6px 14px; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.15s ease; }");
                html.AppendLine("  .btn-filter:hover, .btn-filter.active { background: #2563eb; color: #fff; border-color: #3b82f6; }");
                html.AppendLine("  .search-box { background: #111c29; border: 1px solid #243b56; color: #fff; padding: 8px 14px; border-radius: 6px; font-size: 13px; width: 280px; outline: none; }");
                html.AppendLine("  .search-box:focus { border-color: #3b82f6; }");
                html.AppendLine("  table { width: 100%; border-collapse: collapse; background: #111b27; border: 1px solid #1e3146; border-radius: 8px; overflow: hidden; font-size: 13px; }");
                html.AppendLine("  th { background: #162537; color: #93c5fd; font-weight: 600; text-align: left; padding: 12px 14px; border-bottom: 1px solid #22374e; }");
                html.AppendLine("  td { padding: 10px 14px; border-bottom: 1px solid #1a293a; vertical-align: middle; }");
                html.AppendLine("  tr:hover { background: #152233; }");
                html.AppendLine("  .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }");
                html.AppendLine("  .badge-clean { background: rgba(52, 211, 153, 0.15); color: #34d399; border: 1px solid #059669; }");
                html.AppendLine("  .badge-mod { background: rgba(251, 191, 36, 0.15); color: #fbbf24; border: 1px solid #d97706; }");
                html.AppendLine("  .badge-add { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid #0284c7; }");
                html.AppendLine("  .badge-del { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid #64748b; }");
                html.AppendLine("  .badge-threat { background: rgba(248, 113, 113, 0.2); color: #f87171; border: 1px solid #dc2626; }");
                html.AppendLine("  code { font-family: 'Consolas', 'Courier New', monospace; font-size: 11.5px; color: #94a3b8; }");
                html.AppendLine("  .path-cell { font-family: 'Consolas', 'Courier New', monospace; font-weight: 600; color: #e2e8f0; }");
                html.AppendLine("  footer { text-align: center; margin-top: 32px; font-size: 12px; color: #64748b; }");
                html.AppendLine("</style>");
                html.AppendLine("</head>");
                html.AppendLine("<body>");
                html.AppendLine("<div class='container'>");
                html.AppendLine("  <header>");
                html.AppendLine("    <div class='brand'>");
                html.AppendLine("      <h1>🛡️ HashCheck-Sentinel</h1>");
                html.AppendLine("      <p>Host-Based File Integrity Monitoring & Cryptographic Audit Report</p>");
                html.AppendLine("    </div>");
                html.AppendLine("    <div class='meta'>");
                html.AppendLine($"      <div>Target: <b>{EscapeHtml(root)}</b></div>");
                html.AppendLine($"      <div>Audit Timestamp: <b>{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</b></div>");
                html.AppendLine("    </div>");
                html.AppendLine("  </header>");

                // Metrics
                html.AppendLine("  <div class='cards'>");
                html.AppendLine($"    <div class='card'><div class='card-num'>{totalCount:N0}</div><div class='card-label'>Monitored Files</div></div>");
                html.AppendLine($"    <div class='card'><div class='card-num c-clean'>{unchanged:N0}</div><div class='card-label'>Verified Clean</div></div>");
                html.AppendLine($"    <div class='card'><div class='card-num c-mod'>{modified:N0}</div><div class='card-label'>Modified</div></div>");
                html.AppendLine($"    <div class='card'><div class='card-num c-add'>{added:N0}</div><div class='card-label'>Added</div></div>");
                html.AppendLine($"    <div class='card'><div class='card-num c-del'>{deleted:N0}</div><div class='card-label'>Deleted</div></div>");
                html.AppendLine($"    <div class='card'><div class='card-num c-threat'>{threats:N0}</div><div class='card-label'>Threats / Alerts</div></div>");
                html.AppendLine("  </div>");

                // Crypto Proof
                string merkleRoot = _activeBaseline != null ? _activeBaseline.MerkleRoot : "No Baseline Manifest";
                string hmacSeal = _activeBaseline != null ? _activeBaseline.HmacSeal : "N/A";
                bool isSealValid = _activeBaseline != null && _activeBaseline.IsSealValid;

                html.AppendLine("  <div class='crypto-box'>");
                html.AppendLine("    <div>");
                html.AppendLine("      <div class='crypto-prop'>Merkle Tree Root (RFC 6962 Verification Hash):</div>");
                html.AppendLine($"      <div class='crypto-val'>{EscapeHtml(merkleRoot)}</div>");
                html.AppendLine("    </div>");
                html.AppendLine("    <div>");
                html.AppendLine("      <div class='crypto-prop'>Cryptographic Authenticity Seal:</div>");
                html.AppendLine($"      <div class='crypto-val'>{EscapeHtml(hmacSeal)} &nbsp; " + (isSealValid ? "<span class='seal-verified'>✓ VERIFIED TAMPER-PROOF</span>" : "<span class='seal-tampered'>✗ SIGNATURE MISMATCH / TAMPERED</span>") + "</div>");
                html.AppendLine("    </div>");
                html.AppendLine("  </div>");

                // Toolbar
                html.AppendLine("  <div class='toolbar'>");
                html.AppendLine("    <div class='filters'>");
                html.AppendLine("      <button class='btn-filter active' onclick=\"setFilter('all', this)\">Show All</button>");
                html.AppendLine($"      <button class='btn-filter' onclick=\"setFilter('changes', this)\">🚨 Changes Only ({modified + added + deleted + threats})</button>");
                html.AppendLine($"      <button class='btn-filter' onclick=\"setFilter('threats', this)\">🔴 Threats ({threats})</button>");
                html.AppendLine($"      <button class='btn-filter' onclick=\"setFilter('modified', this)\">🟡 Modified ({modified})</button>");
                html.AppendLine($"      <button class='btn-filter' onclick=\"setFilter('added', this)\">🔵 Added ({added})</button>");
                html.AppendLine($"      <button class='btn-filter' onclick=\"setFilter('deleted', this)\">⚪ Deleted ({deleted})</button>");
                html.AppendLine("    </div>");
                html.AppendLine("    <div>");
                html.AppendLine("      <input type='text' id='searchBox' class='search-box' placeholder='🔍 Search files or hashes...' oninput='onSearchChanged()'>");
                html.AppendLine("    </div>");
                html.AppendLine("  </div>");

                // Table
                html.AppendLine("  <table id='auditTable'>");
                html.AppendLine("    <thead><tr><th>Status</th><th>Relative File Path</th><th>Entropy</th><th>File Size</th><th>SHA-256 Checksum</th><th>Forensic Notes</th></tr></thead>");
                html.AppendLine("    <tbody>");

                // Sort: Threats first, then Modified, Added, Deleted, then Unchanged
                var sortedResults = new List<FileScanResult>(_currentScanResults);
                sortedResults.Sort((a, b) =>
                {
                    int Rank(FileScanResult r)
                    {
                        if (r.Status.Contains("Threat") || !string.IsNullOrEmpty(r.ThreatReason)) return 0;
                        if (r.Status == "Modified") return 1;
                        if (r.Status == "Added") return 2;
                        if (r.Status == "Deleted") return 3;
                        return 4;
                    }
                    int cmp = Rank(a).CompareTo(Rank(b));
                    if (cmp != 0) return cmp;
                    return string.Compare(a.RelativePath, b.RelativePath, StringComparison.OrdinalIgnoreCase);
                });

                const int MaxReportRows = 2000;
                int rendered = 0;
                foreach (var r in sortedResults)
                {
                    if (rendered >= MaxReportRows && r.Status == "Unchanged") continue;
                    rendered++;

                    string statusBadge;
                    string filterTag;
                    if (r.Status.Contains("Threat") || !string.IsNullOrEmpty(r.ThreatReason))
                    {
                        statusBadge = "<span class='badge badge-threat'>🚨 THREAT</span>";
                        filterTag = "threat";
                    }
                    else if (r.Status == "Modified")
                    {
                        statusBadge = "<span class='badge badge-mod'>🟡 MODIFIED</span>";
                        filterTag = "modified";
                    }
                    else if (r.Status == "Added")
                    {
                        statusBadge = "<span class='badge badge-add'>🔵 ADDED</span>";
                        filterTag = "added";
                    }
                    else if (r.Status == "Deleted")
                    {
                        statusBadge = "<span class='badge badge-del'>⚪ DELETED</span>";
                        filterTag = "deleted";
                    }
                    else
                    {
                        statusBadge = "<span class='badge badge-clean'>🟢 CLEAN</span>";
                        filterTag = "clean";
                    }

                    string sizeText = r.FileSize < 1024 ? $"{r.FileSize} B" : $"{r.FileSize / 1024.0:F1} KB";
                    string note = !string.IsNullOrEmpty(r.ThreatReason) ? EscapeHtml(r.ThreatReason) : (r.Status == "Modified" ? "Content differs from baseline" : "—");

                    html.AppendLine($"    <tr data-status='{filterTag}'>");
                    html.AppendLine($"      <td>{statusBadge}</td>");
                    html.AppendLine($"      <td class='path-cell'>{EscapeHtml(r.RelativePath)}</td>");
                    html.AppendLine($"      <td>{r.Entropy:F2} / 8.0</td>");
                    html.AppendLine($"      <td>{sizeText}</td>");
                    html.AppendLine($"      <td><code>{EscapeHtml(r.Sha256)}</code></td>");
                    html.AppendLine($"      <td>{note}</td>");
                    html.AppendLine("    </tr>");
                }

                html.AppendLine("    </tbody>");
                html.AppendLine("  </table>");

                if (rendered < sortedResults.Count)
                {
                    html.AppendLine($"  <p style='margin-top: 14px; font-size: 13px; color: #94a3b8;'>ℹ️ Showing all changes plus first {rendered:N0} files. {sortedResults.Count - rendered:N0} additional unchanged files omitted for report performance.</p>");
                }

                html.AppendLine("  <footer>");
                html.AppendLine("    Generated by HashCheck-Sentinel Autonomous File Integrity Monitor • HMAC-SHA256 & Merkle Tree Cryptographic Verification");
                html.AppendLine("  </footer>");
                html.AppendLine("</div>");

                // JavaScript for Instant Browser Filtering
                html.AppendLine("<script>");
                html.AppendLine("  let currentFilter = 'all';");
                html.AppendLine("  function setFilter(filter, btn) {");
                html.AppendLine("    currentFilter = filter;");
                html.AppendLine("    document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));");
                html.AppendLine("    if (btn) btn.classList.add('active');");
                html.AppendLine("    applyFilter();");
                html.AppendLine("  }");
                html.AppendLine("  function onSearchChanged() { applyFilter(); }");
                html.AppendLine("  function applyFilter() {");
                html.AppendLine("    const term = (document.getElementById('searchBox').value || '').toLowerCase();");
                html.AppendLine("    const rows = document.querySelectorAll('#auditTable tbody tr');");
                html.AppendLine("    rows.forEach(tr => {");
                html.AppendLine("      const st = tr.getAttribute('data-status');");
                html.AppendLine("      let matchStatus = false;");
                html.AppendLine("      if (currentFilter === 'all') matchStatus = true;");
                html.AppendLine("      else if (currentFilter === 'changes') matchStatus = (st !== 'clean');");
                html.AppendLine("      else if (currentFilter === 'threats') matchStatus = (st === 'threat');");
                html.AppendLine("      else if (currentFilter === 'modified') matchStatus = (st === 'modified');");
                html.AppendLine("      else if (currentFilter === 'added') matchStatus = (st === 'added');");
                html.AppendLine("      else if (currentFilter === 'deleted') matchStatus = (st === 'deleted');");
                html.AppendLine("      const text = tr.innerText.toLowerCase();");
                html.AppendLine("      const matchSearch = (!term || text.includes(term));");
                html.AppendLine("      tr.style.display = (matchStatus && matchSearch) ? '' : 'none';");
                html.AppendLine("    });");
                html.AppendLine("  }");
                html.AppendLine("</script>");
                html.AppendLine("</body></html>");

                File.WriteAllText(reportPath, html.ToString(), Encoding.UTF8);
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(reportPath) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to export report: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SetBusyState(bool isBusy, string statusText)
        {
            _btnScan.Enabled = !isBusy;
            _btnBaseline.Enabled = !isBusy;
            if (_btnUpdateBaseline != null) _btnUpdateBaseline.Enabled = !isBusy;
            _progressBar.Visible = isBusy;
            if (isBusy)
            {
                _progressBar.Style = ProgressBarStyle.Marquee;
            }
            else
            {
                _progressBar.Value = 0;
            }
            _lblStatusDetail.Text = statusText;
            Application.DoEvents();
        }

        private void UpdateProgress(ScanProgress prog)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => UpdateProgress(prog)));
                return;
            }

            if (prog.TotalCount > 0)
            {
                if (_progressBar.Style != ProgressBarStyle.Blocks)
                {
                    _progressBar.Style = ProgressBarStyle.Blocks;
                    _progressBar.Minimum = 0;
                    _progressBar.Maximum = 100;
                }
                int pct = (int)Math.Min(100, Math.Max(0, (prog.ProcessedCount * 100.0) / Math.Max(1, prog.TotalCount)));
                _progressBar.Value = pct;
                _lblStatusDetail.Text = $"Scanning ({prog.ProcessedCount:N0}/{prog.TotalCount:N0} • {pct}%) @ {prog.ThroughputMBps:F1} MB/s: {prog.CurrentFile}";
            }
            else
            {
                _lblStatusDetail.Text = $"Scanning ({prog.ProcessedCount:N0}) @ {prog.ThroughputMBps:F1} MB/s: {prog.CurrentFile}";
            }
        }

        // ==========================================
        // EXAMINER DEMONSTRATION LAB HANDLERS
        // ==========================================
        private void RunDemoReset()
        {
            DemoLab.ResetLabToCleanState();
            _txtFolder.Text = DemoLab.GetDemoLabDirectory();
            SetFilter("All");
            CreateBaseline();
        }

        private void RunDemoCase1()
        {
            string demoDir = DemoLab.GetDemoLabDirectory();
            if (!string.Equals(_txtFolder.Text, demoDir, StringComparison.OrdinalIgnoreCase))
            {
                _txtFolder.Text = demoDir;
            }
            DemoLab.TriggerScenario1_CodeInjection();
            SetFilter("Modified");
            RunScan();
            MessageBox.Show(
                "🧪 Scenario 1 Executed: Unauthorized Backdoor Injected into server_config.py!\n\n" +
                "• Integrity Result: Flagged as '🟡 MODIFIED'\n" +
                "• Demonstration: Double-click the row (or press Enter) to open the Forensic Diff Dialog.\n" +
                "• Technical Defense: Solves the 'Avalanche Effect' of hashing by showing exact green (+) added lines and red (-) deleted lines.",
                "Examiner Scenario 1: Backdoor Code Injection",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void RunDemoCase2()
        {
            string demoDir = DemoLab.GetDemoLabDirectory();
            if (!string.Equals(_txtFolder.Text, demoDir, StringComparison.OrdinalIgnoreCase))
            {
                _txtFolder.Text = demoDir;
            }
            DemoLab.TriggerScenario2_RansomwareAttack();
            SetFilter("Threats");
            RunScan();
            MessageBox.Show(
                "🧪 Scenario 2 Executed: AES Ransomware Attack Simulated!\n\n" +
                "• Integrity Result: Flagged as '🚨 Threat: Encrypted'\n" +
                "• Demonstration: Shannon Entropy surged from 3.8 to 7.95 / 8.00 bits/byte.\n" +
                "• Technical Defense: Demonstrates signatureless zero-day ransomware detection using Claude Shannon's Information Entropy formula.",
                "Examiner Scenario 2: Active Ransomware Attack",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }

        private void RunDemoCase3()
        {
            string demoDir = DemoLab.GetDemoLabDirectory();
            if (!string.Equals(_txtFolder.Text, demoDir, StringComparison.OrdinalIgnoreCase))
            {
                _txtFolder.Text = demoDir;
            }
            DemoLab.TriggerScenario3_BaselineForgery();
            RunScan();
            MessageBox.Show(
                "🧪 Scenario 3 Executed: Baseline Manifest Tampered in Notepad!\n\n" +
                "• Integrity Result: Critical Alarm '🚨 CRITICAL: BASELINE INTEGRITY SEAL BROKEN!'\n" +
                "• Demonstration: HMAC-SHA256 signature verification failed.\n" +
                "• Technical Defense: Proves attackers with local administrator access cannot conceal malware by altering the baseline manifest.",
                "Examiner Scenario 3: Baseline Tampering",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        private void RunDemoCase4()
        {
            string demoDir = DemoLab.GetDemoLabDirectory();
            if (!string.Equals(_txtFolder.Text, demoDir, StringComparison.OrdinalIgnoreCase))
            {
                _txtFolder.Text = demoDir;
            }
            DemoLab.TriggerScenario4_Steganography();
            SetFilter("Threats");
            RunScan();
            MessageBox.Show(
                "🧪 Scenario 4 Executed: Stealth Shellcode Appended to audit_badge.png!\n\n" +
                "• Integrity Result: Flagged as 'Steganography / Trailing Bytes Detected'\n" +
                "• Demonstration: Structural file parser identified executable bytes past PNG IEND termination chunk.\n" +
                "• Technical Defense: Proves detection of covert malware distribution channels.",
                "Examiner Scenario 4: Steganography Hidden Payload",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        protected override void OnLoad(EventArgs e)
        {
            Program.LogCrash("MainForm.OnLoad");
            base.OnLoad(e);
        }

        protected override void OnShown(EventArgs e)
        {
            Program.LogCrash("MainForm.OnShown");
            base.OnShown(e);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            Program.LogCrash($"MainForm.OnFormClosing: CloseReason={e.CloseReason}, Cancel={e.Cancel}");
            _liveWatcher?.Dispose();
            base.OnFormClosing(e);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            Program.LogCrash($"MainForm.OnFormClosed: CloseReason={e.CloseReason}");
            base.OnFormClosed(e);
        }
    }
}
