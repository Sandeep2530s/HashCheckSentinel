# 🛡️ HashCheck-Sentinel (SentinelFIM)
### An Integrated Real-Time File Integrity Monitoring and Content-Differential Forensic System

---

## 📌 Executive Summary
**HashCheck-Sentinel** is an autonomous, host-based File Integrity Monitoring (FIM) and ransomware early-warning system for Windows. Built to transcend the limitations of traditional, reactive hash checkers, Sentinel combines **multi-core parallel hashing**, **Claude Shannon's Information Entropy heuristics**, **HMAC-SHA256 cryptographic baseline sealing**, **Merkle Tree state verification**, and **Myers Diff granular content forensics**.

---

## 🚀 Key Innovations & Architectural Pillars

| Pillar | Engineering Mechanism | Problem Solved |
| :--- | :--- | :--- |
| **1. "What Changed" Diff Forensics** | Myers Diff / LCS Dynamic Programming algorithm ($O(ND)$ complexity) | Solves the **Avalanche Effect** of hashing. Shows exact added lines in **Green (+)** and deleted lines in **Red (-)** instead of just saying "hash modified". |
| **2. Cryptographic Tamper Seal** | **HMAC-SHA256 (RFC 2104)** computed across all baseline records using hardware-derived keys | Prevents attackers or malware from opening the baseline in Notepad and altering hashes to conceal their intrusions. |
| **3. Ransomware Early Warning** | **Claude Shannon Information Entropy** ($H(X) = -\sum P(x) \log_2 P(x)$) | Detects active zero-day encryption attacks when file entropy surges towards $7.92–8.00$ bits/byte across rapid write bursts. |
| **4. Multi-Core Parallel Throughput** | `Parallel.ForEach` across all CPU cores + 64 KB streaming buffers | Scans tens of thousands of files at SSD bus speeds without freezing the UI or exceeding system RAM. |
| **5. Producer-Consumer Live Watcher** | Windows `FileSystemWatcher` (64 KB OS buffer) + `ConcurrentQueue` + 350ms debouncing | Monitors file activity 24/7 without manual scanning or dropping events during mass file creation. |
| **6. "Exceptions-First" UI** | Management-by-Exception filter | Eliminates "Alert Fatigue" by displaying only modified, added, deleted, or threatened files by default. |
| **7. Rolling Storage Retention** | Maintains 1 active baseline + 3 versioned snapshots with automated pruning | Guarantees disk consumption remains permanently under **20 MB**. |
| **8. Examiner Demonstration Lab** | Built-in test sandbox with 4 one-click simulated attack scenarios | Allows flawless, repeatable, 2-minute live demonstrations during academic vivas. |

---

## 💻 How to Run the Application

A pre-built standalone executable is included in the `release/` folder:
- **`release/HashCheckSentinel.exe`** (Ready to run on Windows, no setup or dependencies needed!)

1. **Double-click** `release/HashCheckSentinel.exe` to launch the application.
2. The modern dark-navy dashboard will appear.

To build from source:
```cmd
msbuild HashCheckSentinel.csproj /p:Configuration=Release
```

---

## 🎓 Demonstration Walkthrough 

When demonstrating to professors, toggle the top-right radio button to **🎓 Examiner Lab**. 
A dedicated demonstration panel will appear with 4 pre-packaged scenarios:

### Scenario 1: Backdoor Injection & Visual Diff
1. Click **`[ 🔄 Reset Lab ]`** to create clean baseline files in the sandbox.
2. Click **`[ ▶ Case 1: Code Backdoor ]`**.
   * An unauthorized backdoor bypass and exfiltration endpoint are injected into `server_config.py`.
   * The app flags the file in **Yellow (`Modified`)**.
3. **Double-click the row** in the table:
   * The **Forensic Inspection Dialog** opens.
   * Point out the **Green (+) lines** showing the exact injected backdoor code and **Red (-) lines** showing deleted original code!

### Scenario 2: Active Ransomware Attack
1. Click **`[ ▶ Case 2: Ransomware Attack ]`**.
   * `system_notes.txt` and `security_policy.json` are encrypted using AES.
   * The app flashes a **Red Alert: `🚨 Threat: Encrypted`**.
2. **Double-click the row**:
   * Switch to the **Forensic Metadata tab**.
   * Show the professors the **Shannon Entropy Spike** ($3.8 \rightarrow 7.95 / 8.0$), proving how your mathematical model detected ransomware without needing signatures.

### Scenario 3: Baseline Tampering (Attacker Evasion Attempt)
1. Click **`[ ▶ Case 3: Tampered Baseline ]`**.
   * Simulates an attacker modifying the baseline file to hide their changes.
   * The app detects the signature mismatch and sounds a **Critical Alarm: `🚨 BASELINE INTEGRITY SEAL BROKEN!`**.

### Scenario 4: Steganography (Hidden Malware in Images)
1. Click **`[ ▶ Case 4: Steganography ]`**.
   * A shellcode payload is appended past the PNG `IEND` end marker.
   * The app detects the trailing byte anomaly and flags **`Steganography Detected`**.

### Resetting the Demo:
* Click **`[ 🔄 Reset Lab ]`** at any time to restore all files to their pristine state and re-seal the baseline in 1 second.

---

## 📑 Exporting Forensic Audit Reports
Click **`[ 📑 Export HTML Report ]`** on the toolbar to generate a professional, printable HTML audit report conforming to **NIST SP 800-145 / ISO 27001** file auditing standards.

---

## 📚 Project Architecture & File Structure

```
HashCheckSentinel/
├── HashCheckSentinel.csproj       # Project build specification
├── Program.cs                     # Application bootstrap
├── MainForm.cs                    # High-performance WinForms dashboard
├── release/
│   └── HashCheckSentinel.exe      # Precompiled standalone Windows executable
├── Core/
│   ├── Hasher.cs                 # Multi-core streaming hash engine & path normalizer
│   ├── EntropyCalculator.cs       # Shannon entropy & format magic byte analysis
│   ├── BaselineManager.cs         # HMAC-SHA256 sealing, Merkle root & rolling retention
│   ├── DiffEngine.cs              # Myers Diff (LCS) & binary delta inspector
│   ├── LiveWatcher.cs             # Producer-consumer kernel watcher pipeline
│   ├── OfficeTextExtractor.cs     # Forensic text extractor for DOCX / Office files
│   └── DemoLab.cs                 # Pre-packaged examiner demonstration sandbox
└── UI/
    ├── DiffDialog.cs              # Interactive line-by-line colored diff modal
    ├── TeacherDemoDialog.cs       # Guided teacher/examiner walkthrough modal
    └── TheoryDialog.cs            # Academic viva defense formula reference
```

---

## ⌨️ Professional Keyboard Shortcuts & Hotkeys

| Shortcut | Command / Action | Description |
| :--- | :--- | :--- |
| **`F5`** | **Multi-Core Scan** | Executes parallel streaming scan across all CPU cores |
| **`Ctrl + S`** | **Accept & Update Baseline** | Seals all verified changes into baseline with Merkle & HMAC |
| **`Ctrl + O`** | **Browse Monitored Directory** | Open folder selection dialog |
| **`Ctrl + F`** | **Live Search Bar** | Instantly focus and filter files by path, status, or hash |
| **`Ctrl + R`** | **Export Forensic Audit Report** | Generates executive HTML audit report with crypto proofs |
| **`F1`** | **Security Architecture** | Displays mathematical entropy formulas & RFC 2104 proofs |
| **`Enter`** | **Inspect Content Diff** | Opens line-by-line colored diff modal for selected row |

---

## 🖱️ Context Menu & Forensic Action Tools

Right-clicking any row in the forensic grid reveals professional incident response tools:
* **🔍 Inspect Content / Forensic Diff (`Enter`)**: Side-by-side green (+) / red (-) Myers visual diff.
* **📁 Show in Windows Explorer**: Automatically selects the file in Windows Explorer for inspection.
* **📋 Copy Relative Path / Full Path**: Copies normalized file path to system clipboard.
* **📋 Copy SHA-256 Hash**: Copies complete 64-character hexadecimal cryptographic hash.
* **🔄 Accept This File into Baseline**: Granularly accepts a single file change into the baseline without accepting unrelated changes, atomically updating the Merkle tree root and HMAC signature.

---

