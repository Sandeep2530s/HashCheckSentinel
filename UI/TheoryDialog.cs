using System;
using System.Drawing;
using System.Windows.Forms;

namespace HashCheckSentinel.UI
{
    public sealed class TheoryDialog : Form
    {
        public TheoryDialog()
        {
            Text = "Academic Architecture & Cryptographic Theory (Viva Defense Reference)";
            Width = 860;
            Height = 600;
            MinimumSize = new Size(700, 480);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Color.FromArgb(16, 26, 40);
            ForeColor = Color.White;

            var rtb = new RichTextBox
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 10F),
                BackColor = Color.FromArgb(20, 30, 45),
                ForeColor = Color.Gainsboro,
                ReadOnly = true,
                Padding = new Padding(12)
            };

            string content = @"========================================================================================
     HASHCHECK-SENTINEL: ACADEMIC CRYPTOGRAPHY & ALGORITHMIC ARCHITECTURE
========================================================================================

1. CLAUDE SHANNON'S INFORMATION ENTROPY (RANSOMWARE HEURISTIC)
----------------------------------------------------------------------------------------
Mathematical Formulation:
     H(X) = - SUM_{i=0}^{255} P(x_i) * log_2(P(x_i))

• Definition: Quantifies the average information density and randomness per byte.
• Scale: 0.00 bits/byte (pure uniformity) to 8.00 bits/byte (maximal randomness).
• Thresholds:
   - Plain Text / Source Code:  3.20 - 5.40 bits/byte
   - Structured Media / Docs:   5.50 - 7.20 bits/byte
   - AES / RSA Encrypted Files: 7.92 - 8.00 bits/byte (Approaches theoretical maximum)
• Forensic Innovation:
   When multiple files exhibit an entropy surge (Delta >= 1.5) reaching >= 7.90, the system
   flags active, unauthorized cryptographic encryption (Zero-Day Ransomware Outbreak).


2. CRYPTOGRAPHIC TAMPER-PROOF SEAL (HMAC-SHA256 - RFC 2104)
----------------------------------------------------------------------------------------
Formulation:
     HMAC(K, M) = SHA-256( (K XOR opad) || SHA-256( (K XOR ipad) || M ) )

• Purpose: Solves the fundamental vulnerability where attackers modify baseline hashes.
• Integrity Proof:
   The baseline manifest is cryptographically signed using a machine-derived secret key.
   If an adversary alters a single byte or hash inside the baseline file in Notepad,
   the calculated signature diverges from the stored seal, raising an immediate Tamper Alarm.


3. HIERARCHICAL MERKLE TREE VERIFICATION (BINARY HASH TREE)
----------------------------------------------------------------------------------------
• Complexity: O(log N) verification of any individual leaf node.
• Root Representation:
   Combines all sorted SHA-256 hashes pairwise into a single 64-character Root Hash.
   The Merkle Root provides an unforgeable, mathematical fingerprint of the entire host state.


4. CONTENT-DIFFERENTIAL FORENSICS (MYERS DIFF / LCS ALGORITHM)
----------------------------------------------------------------------------------------
• Problem Solved: Overcomes the 'Avalanche Effect' of cryptographic hashing. A hash only
  reveals THAT a file changed; Myers Diff algorithm reveals EXACTLY WHAT content changed.
• Complexity: O(ND) where N = line count, D = minimal edit script size.
• Output: Line-by-line attribution of added (+) and deleted (-) lines in human-readable diff.


5. PRODUCER-CONSUMER LIVE KERNEL EVENT PIPELINE
----------------------------------------------------------------------------------------
• Intercepts Windows I/O events with 64 KB internal OS buffer.
• Employs a ConcurrentQueue memory decouple with debouncing (350ms window) to prevent
  event drop during mass write bursts (e.g., archive extraction or ransomware sweeps).
========================================================================================";

            rtb.Text = content;

            var footer = new Panel { Dock = DockStyle.Bottom, Height = 48, BackColor = Color.FromArgb(12, 20, 32) };
            var btnClose = new Button
            {
                Text = "Close",
                Width = 90, Height = 30,
                Left = Width - 130, Top = 9,
                Anchor = AnchorStyles.Right | AnchorStyles.Top,
                BackColor = Color.FromArgb(50, 110, 180),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnClose.Click += (s, e) => Close();
            footer.Controls.Add(btnClose);

            Controls.Add(rtb);
            Controls.Add(footer);
        }
    }
}
