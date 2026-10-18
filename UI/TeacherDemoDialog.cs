using System;
using System.Drawing;
using System.Windows.Forms;

namespace HashCheckSentinel.UI
{
    /// <summary>
    /// Comprehensive interactive demonstration guide designed specifically for academic examiners,
    /// professors, and viva evaluators. Explains the security theory, attack mechanisms, and evaluation rubric.
    /// </summary>
    public sealed class TeacherDemoDialog : Form
    {
        private readonly Action _onReset;
        private readonly Action _onCase1;
        private readonly Action _onCase2;
        private readonly Action _onCase3;
        private readonly Action _onCase4;

        public TeacherDemoDialog(Action onReset, Action onCase1, Action onCase2, Action onCase3, Action onCase4)
        {
            _onReset = onReset;
            _onCase1 = onCase1;
            _onCase2 = onCase2;
            _onCase3 = onCase3;
            _onCase4 = onCase4;

            Text = "🎓 SentinelFIM — Teacher & Examiner Demonstration Guide";
            Width = 980;
            Height = 680;
            MinimumSize = new Size(860, 560);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Color.FromArgb(15, 23, 42);
            ForeColor = Color.White;

            // 1. TOP HEADER
            var pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 85,
                BackColor = Color.FromArgb(10, 16, 30),
                Padding = new Padding(24, 16, 24, 16)
            };

            var lblTitle = new Label
            {
                Text = "🎓 Academic Examiner & Teacher Demonstration Guide",
                Font = new Font("Segoe UI", 15F, FontStyle.Bold),
                ForeColor = Color.FromArgb(129, 140, 248),
                AutoSize = true,
                Left = 24,
                Top = 14
            };

            var lblSubtitle = new Label
            {
                Text = "Interactive test lab and evaluation rubric designed for live viva examinations and defense presentations.",
                Font = new Font("Segoe UI", 9F),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Left = 26,
                Top = 44
            };

            var btnHeaderReset = new Button
            {
                Text = "🧹 Reset Clean Sandbox",
                Width = 180,
                Height = 36,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Left = pnlHeader.Width - 210,
                Top = 22,
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            btnHeaderReset.FlatAppearance.BorderSize = 0;
            btnHeaderReset.Click += (s, e) =>
            {
                _onReset?.Invoke();
                MessageBox.Show("Sandbox lab reset to clean state with initial verified baseline!", "Sandbox Reset Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            pnlHeader.Controls.AddRange(new Control[] { lblTitle, lblSubtitle, btnHeaderReset });

            // 2. MAIN TABBED SCENARIO CONTAINER
            var tabs = new TabControl
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Padding = new Point(14, 8)
            };

            tabs.TabPages.Add(CreateScenarioTab(
                "1. Code Backdoor Injection",
                "Scenario 1: Unauthorized Code Backdoor Injection",
                "server_config.py",
                "Integrity Violation (Modified)",
                "Simulates an adversary gaining internal access and modifying server_config.py to insert an unauthorized privilege escalation backdoor ('hacked_bypass') and exfiltration endpoint.",
                "Traditional hashing tools only report 'Hash Mismatch' (the Avalanche Effect). Sentinel goes beyond basic hashing by executing the Myers Longest Common Subsequence (LCS) Diff Algorithm in O(ND) time to isolate the exact added lines in Green (+) and deleted lines in Red (-).",
                new string[]
                {
                    "1. Click the button below to inject the backdoor.",
                    "2. Point out the Yellow 'Modified' status row in the dashboard.",
                    "3. Double-click the row (or press Enter) to open the Forensic Diff Dialog.",
                    "4. Show the professors the green lines revealing the exact backdoor code inserted by the attacker!"
                },
                "▶ Run Scenario 1: Inject Backdoor",
                Color.FromArgb(217, 119, 6),
                _onCase1
            ));

            tabs.TabPages.Add(CreateScenarioTab(
                "2. AES Ransomware Outbreak",
                "Scenario 2: Active Zero-Day Ransomware Outbreak",
                "system_notes.txt & security_policy.json",
                "Ransomware / High Entropy Surge",
                "Simulates a ransomware attack that rapidly encrypts user files using standard AES-256 block ciphers.",
                "Traditional antivirus relies on signature databases that fail against zero-day ransomware. Sentinel utilizes Claude Shannon's Information Entropy Formula:\n   H(X) = - SUM( P(x) * log2(P(x)) )\nEncrypted ciphertext approaches maximal theoretical randomness (7.92 - 8.00 bits/byte). When multiple files surge from normal entropy (3.2 - 5.4) to > 7.85 bits/byte, Sentinel triggers an immediate active ransomware alert.",
                new string[]
                {
                    "1. Click the button below to trigger the ransomware simulation.",
                    "2. Notice the instant Red Alert: '🚨 Threat: Encrypted'.",
                    "3. Double-click the affected file to inspect the Forensic Metadata tab.",
                    "4. Point out the Shannon Entropy surge to 7.95 / 8.00 bits/byte, proving signatureless ransomware detection!"
                },
                "▶ Run Scenario 2: Simulate Ransomware",
                Color.FromArgb(220, 38, 38),
                _onCase2
            ));

            tabs.TabPages.Add(CreateScenarioTab(
                "3. Baseline Manifest Tampering",
                "Scenario 3: Attacker Attempts to Forgery/Edit Baseline",
                ".sentinel-baseline/active_baseline.sentinel",
                "Cryptographic Seal Broken (Alarm)",
                "Simulates an advanced persistent threat (APT) who attempts to bypass detection by opening the baseline file in Notepad and editing stored hashes to match their trojanized binaries.",
                "In naive FIM tools, an attacker with local admin rights can simply edit the stored hash manifest. Sentinel prevents this using HMAC-SHA256 (RFC 2104) keyed with machine-hardware entropy. Any manual modification alters the cryptographic hash tree and breaks the HMAC signature.",
                new string[]
                {
                    "1. Click the button below to simulate tampering with the baseline manifest.",
                    "2. Observe the Critical Alert banner: '🚨 CRITICAL: BASELINE INTEGRITY SEAL BROKEN!'.",
                    "3. Explain to the examiner that HMAC-SHA256 guarantees unforgeable baseline authenticity."
                },
                "▶ Run Scenario 3: Tamper Baseline",
                Color.FromArgb(147, 51, 234),
                _onCase3
            ));

            tabs.TabPages.Add(CreateScenarioTab(
                "4. Steganography Payload",
                "Scenario 4: Hidden Malware Shellcode in Image File",
                "audit_badge.png",
                "Steganography / Trailing Byte Anomaly",
                "Simulates an attacker appending stealth shellcode payload after the legitimate end-of-file (IEND chunk) of an innocent PNG image.",
                "Standard hash tools cannot identify why a file changed or what is hidden. Sentinel inspects format-specific magic bytes and structural bounds (PNG, JPEG, PDF), detecting covert executable bytes appended past file termination markers.",
                new string[]
                {
                    "1. Click the button below to inject stealth shellcode into the image.",
                    "2. Observe the threat status: 'Steganography / Trailing Bytes Detected'.",
                    "3. Double-click the file to inspect the structural EOF anomaly in the forensic dialog."
                },
                "▶ Run Scenario 4: Inject Stego Payload",
                Color.FromArgb(13, 148, 136),
                _onCase4
            ));

            // 3. BOTTOM CLOSE STRIP
            var pnlBottom = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 52,
                BackColor = Color.FromArgb(10, 16, 30),
                Padding = new Padding(20, 10, 20, 10)
            };

            var lblBottomHint = new Label
            {
                Text = "💡 Tip for Viva: Running any scenario above automatically switches the dashboard to the Sandbox and executes a multi-core scan.",
                Font = new Font("Segoe UI", 9F, FontStyle.Italic),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Left = 20,
                Top = 16
            };

            var btnClose = new Button
            {
                Text = "Close Guide",
                Width = 110,
                Height = 32,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Left = pnlBottom.Width - 130,
                Top = 10,
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => Close();

            pnlBottom.Controls.AddRange(new Control[] { lblBottomHint, btnClose });

            Controls.Add(tabs);
            Controls.Add(pnlHeader);
            Controls.Add(pnlBottom);
        }

        private TabPage CreateScenarioTab(
            string tabHeader,
            string scenarioTitle,
            string targetFile,
            string threatCategory,
            string attackDescription,
            string detectionTheory,
            string[] evaluationSteps,
            string actionButtonText,
            Color actionColor,
            Action actionToExecute)
        {
            var tab = new TabPage(tabHeader)
            {
                BackColor = Color.FromArgb(15, 23, 42),
                Padding = new Padding(24, 18, 24, 18),
                AutoScroll = true
            };

            var pnlContainer = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true
            };

            int currentTop = 10;

            // Scenario Title
            var lblTitle = new Label
            {
                Text = scenarioTitle,
                Font = new Font("Segoe UI", 13F, FontStyle.Bold),
                ForeColor = Color.FromArgb(248, 250, 252),
                AutoSize = true,
                Left = 10,
                Top = currentTop
            };
            pnlContainer.Controls.Add(lblTitle);
            currentTop += 34;

            // Target & Category Badges
            var lblBadges = new Label
            {
                Text = $"Target File: {targetFile}   |   Threat Classification: {threatCategory}",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Left = 12,
                Top = currentTop
            };
            pnlContainer.Controls.Add(lblBadges);
            currentTop += 30;

            // Section 1: Attack Mechanism
            var lblAttackHeader = new Label
            {
                Text = "📌 Attack Mechanism (What the Attacker Does):",
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                AutoSize = true,
                Left = 12,
                Top = currentTop
            };
            pnlContainer.Controls.Add(lblAttackHeader);
            currentTop += 24;

            var lblAttackBody = new Label
            {
                Text = attackDescription,
                Font = new Font("Segoe UI", 9.5F),
                ForeColor = Color.FromArgb(203, 213, 225),
                Width = 880,
                Height = 44,
                Left = 14,
                Top = currentTop
            };
            pnlContainer.Controls.Add(lblAttackBody);
            currentTop += 46;

            // Section 2: Detection Theory
            var lblTheoryHeader = new Label
            {
                Text = "🔬 Detection Theory & Mathematical Formulation (What Sentinel Does):",
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                AutoSize = true,
                Left = 12,
                Top = currentTop
            };
            pnlContainer.Controls.Add(lblTheoryHeader);
            currentTop += 24;

            var lblTheoryBody = new Label
            {
                Text = detectionTheory,
                Font = new Font("Segoe UI", 9.5F),
                ForeColor = Color.FromArgb(203, 213, 225),
                Width = 880,
                Height = 85,
                Left = 14,
                Top = currentTop
            };
            pnlContainer.Controls.Add(lblTheoryBody);
            currentTop += 90;

            // Section 3: Viva Checklist
            var lblRubricHeader = new Label
            {
                Text = "✅ Viva Demonstration Walkthrough (What to Show the Teachers):",
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                AutoSize = true,
                Left = 12,
                Top = currentTop
            };
            pnlContainer.Controls.Add(lblRubricHeader);
            currentTop += 24;

            string stepsText = string.Join("\n", evaluationSteps);
            var lblSteps = new Label
            {
                Text = stepsText,
                Font = new Font("Segoe UI", 9.5F),
                ForeColor = Color.FromArgb(147, 197, 253),
                Width = 880,
                Height = 75,
                Left = 14,
                Top = currentTop
            };
            pnlContainer.Controls.Add(lblSteps);
            currentTop += 80;

            // Action Button
            var btnAction = new Button
            {
                Text = actionButtonText,
                Width = 320,
                Height = 40,
                Left = 14,
                Top = currentTop,
                BackColor = actionColor,
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            btnAction.FlatAppearance.BorderSize = 0;
            btnAction.Click += (s, e) =>
            {
                actionToExecute?.Invoke();
                Close();
            };
            pnlContainer.Controls.Add(btnAction);

            tab.Controls.Add(pnlContainer);
            return tab;
        }
    }
}
