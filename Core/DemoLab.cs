using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace HashCheckSentinel.Core
{
    public static class DemoLab
    {
        public static string GetDemoLabDirectory()
        {
            string appDir = null;
            try
            {
                string asmPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                if (!string.IsNullOrEmpty(asmPath) && File.Exists(asmPath))
                {
                    appDir = Path.GetDirectoryName(asmPath);
                }
            }
            catch { }

            if (string.IsNullOrEmpty(appDir))
            {
                appDir = AppDomain.CurrentDomain.BaseDirectory;
            }

            string labDir = Path.Combine(appDir, "ExaminerDemoLab");
            try
            {
                if (!Directory.Exists(labDir))
                {
                    Directory.CreateDirectory(labDir);
                }
                return labDir;
            }
            catch
            {
                string fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HashCheckSentinel", "ExaminerDemoLab");
                if (!Directory.Exists(fallback)) Directory.CreateDirectory(fallback);
                return fallback;
            }
        }

        public static void ResetLabToCleanState()
        {
            string labDir = GetDemoLabDirectory();

            // 1. Clean existing files
            foreach (var file in Directory.GetFiles(labDir))
            {
                try { File.Delete(file); } catch { }
            }

            // Clean existing baseline
            string baseDir = Path.Combine(labDir, ".sentinel-baseline");
            if (Directory.Exists(baseDir))
            {
                try { Directory.Delete(baseDir, true); } catch { }
            }

            // 2. Create clean sample files
            string pyContent = @"# Server Configuration Module
SERVER_HOST = ""127.0.0.1""
SERVER_PORT = 8080
DEBUG_MODE = False
ALLOWED_ROLES = [""admin"", ""auditor""]

def authenticate(user, token):
    if user in ALLOWED_ROLES and len(token) > 16:
        return True
    return False
";
            File.WriteAllText(Path.Combine(labDir, "server_config.py"), pyContent, Encoding.UTF8);

            string jsonContent = @"{
  ""systemName"": ""FinancePortal"",
  ""environment"": ""Production"",
  ""maxLoginAttempts"": 3,
  ""requireMfa"": true,
  ""encryptionAlgorithm"": ""AES-256-GCM""
}";
            File.WriteAllText(Path.Combine(labDir, "security_policy.json"), jsonContent, Encoding.UTF8);

            string txtContent = @"CONFIDENTIAL SYSTEM LOG
2026-10-09 10:00:00 - Routine security audit completed.
2026-10-09 11:30:00 - Database integrity checksum verified.
2026-10-09 14:15:00 - All cryptographic services running normally.
";
            File.WriteAllText(Path.Combine(labDir, "system_notes.txt"), txtContent, Encoding.UTF8);

            // Create a minimal 1x1 valid PNG image
            byte[] cleanPng = new byte[]
            {
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG Magic Header
                0x00, 0x00, 0x00, 0x0D,                         // IHDR Length = 13
                0x49, 0x48, 0x44, 0x52,                         // "IHDR"
                0x00, 0x00, 0x00, 0x01,                         // Width = 1
                0x00, 0x00, 0x00, 0x01,                         // Height = 1
                0x08, 0x02, 0x00, 0x00, 0x00,                   // 8-bit RGB
                0x90, 0x77, 0x53, 0xDE,                         // IHDR CRC
                0x00, 0x00, 0x00, 0x0C,                         // IDAT Length = 12
                0x49, 0x44, 0x41, 0x54,                         // "IDAT"
                0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00,
                0x18, 0xDD, 0x8D, 0xB0,                         // IDAT CRC
                0x00, 0x00, 0x00, 0x00,                         // IEND Length = 0
                0x49, 0x45, 0x4E, 0x44,                         // "IEND"
                0xAE, 0x42, 0x60, 0x82                          // IEND CRC
            };
            File.WriteAllBytes(Path.Combine(labDir, "audit_badge.png"), cleanPng);
        }

        public static void TriggerScenario1_CodeInjection()
        {
            string labDir = GetDemoLabDirectory();
            string pyPath = Path.Combine(labDir, "server_config.py");
            if (!File.Exists(pyPath)) return;

            string modified = @"# Server Configuration Module
SERVER_HOST = ""127.0.0.1""
SERVER_PORT = 9999
DEBUG_MODE = True
ALLOWED_ROLES = [""admin"", ""auditor"", ""backdoor_root""]
EXFILTRATION_ENDPOINT = ""http://c2-malicious.onion/data""

def authenticate(user, token):
    # INJECTED BACKDOOR BYPASS
    if user == ""backdoor_root"": return True
    if user in ALLOWED_ROLES and len(token) > 16:
        return True
    return False
";
            File.WriteAllText(pyPath, modified, Encoding.UTF8);
        }

        public static void TriggerScenario2_RansomwareAttack()
        {
            string labDir = GetDemoLabDirectory();
            string[] targetFiles = new[] { "system_notes.txt", "security_policy.json" };

            // Encrypt using AES to achieve maximal Shannon Entropy (~7.95)
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }

            foreach (var name in targetFiles)
            {
                string path = Path.Combine(labDir, name);
                if (File.Exists(path))
                {
                    byte[] original = File.ReadAllBytes(path);
                    using (var aes = Aes.Create())
                    {
                        aes.Key = key;
                        aes.IV = iv;
                        using (var ms = new MemoryStream())
                        {
                            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                            {
                                cs.Write(original, 0, original.Length);
                                cs.FlushFinalBlock();
                            }
                            // Overwrite file with encrypted payload + ransomware banner
                            byte[] cipher = ms.ToArray();
                            File.WriteAllBytes(path, cipher);
                        }
                    }
                }
            }
        }

        public static void TriggerScenario3_BaselineForgery()
        {
            string labDir = GetDemoLabDirectory();
            string activeBaseline = Path.Combine(labDir, ".sentinel-baseline", "active_baseline.fim");
            if (!File.Exists(activeBaseline)) return;

            // An attacker manually tampers with baseline hashes inside active_baseline.fim
            string content = File.ReadAllText(activeBaseline, Encoding.UTF8);
            string tampered = content.Replace("server_config.py", "server_config.py|FORGED_HASH_3b7a1c90");
            File.WriteAllText(activeBaseline, tampered, Encoding.UTF8);
        }

        public static void TriggerScenario4_Steganography()
        {
            string labDir = GetDemoLabDirectory();
            string pngPath = Path.Combine(labDir, "audit_badge.png");
            if (!File.Exists(pngPath)) return;

            // Append hidden shellcode payload after valid IEND chunk
            byte[] payload = Encoding.UTF8.GetBytes("HIDDEN_PAYLOAD_SHELLCODE: cmd.exe /c powershell -enc aW52b2tlLWV4cHJlc3Npb24...");
            using (var fs = new FileStream(pngPath, FileMode.Append, FileAccess.Write))
            {
                fs.Write(payload, 0, payload.Length);
            }
        }
    }
}
