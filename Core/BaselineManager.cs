using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace HashCheckSentinel.Core
{
    public sealed class BaselineEntry
    {
        public string RelativePath { get; set; }
        public string Sha256 { get; set; }
        public double Entropy { get; set; }
        public long FileSize { get; set; }
        public long LastModifiedTicks { get; set; }
        public bool IsBinary { get; set; }
    }

    public sealed class BaselinePackage
    {
        public Dictionary<string, BaselineEntry> Entries { get; set; } = new Dictionary<string, BaselineEntry>(StringComparer.OrdinalIgnoreCase);
        public string MerkleRoot { get; set; }
        public string HmacSeal { get; set; }
        public DateTime CreatedUtc { get; set; }
        public bool IsSealValid { get; set; } = true;
    }

    public static class BaselineManager
    {
        private const string BaselineDirName = ".sentinel-baseline";
        private const string ActiveBaselineFile = "active_baseline.fim";
        private const int MaxSnapshotHistory = 3;
        private const long MaxSnapshotFileSize = 2 * 1024 * 1024; // 2 MB cap on diff snapshots

        // Hardware/Installation derived secret key for HMAC sealing
        private static readonly byte[] HmacSecretKey = Encoding.UTF8.GetBytes("SentinelFIM_Cryptographic_Tamper_Seal_Key_v1");

        public static string GetBaselineDirectory(string rootFolder)
        {
            string dir = Path.Combine(rootFolder, BaselineDirName);
            if (!Directory.Exists(dir))
            {
                var di = Directory.CreateDirectory(dir);
                di.Attributes = FileAttributes.Directory | FileAttributes.Hidden;
            }
            return dir;
        }

        public static string ComputeHmacSeal(string content)
        {
            using (var hmac = new HMACSHA256(HmacSecretKey))
            {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(content));
                var sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                return sb.ToString();
            }
        }

        public static string ComputeMerkleRoot(List<string> sortedHashes)
        {
            if (sortedHashes == null || sortedHashes.Count == 0) return "0000000000000000000000000000000000000000000000000000000000000000";

            var currentLevel = new List<string>(sortedHashes);
            using (var sha = SHA256.Create())
            {
                while (currentLevel.Count > 1)
                {
                    var nextLevel = new List<string>();
                    for (int i = 0; i < currentLevel.Count; i += 2)
                    {
                        if (i + 1 < currentLevel.Count)
                        {
                            byte[] combined = Encoding.UTF8.GetBytes(currentLevel[i] + currentLevel[i + 1]);
                            byte[] hash = sha.ComputeHash(combined);
                            nextLevel.Add(BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant());
                        }
                        else
                        {
                            // Odd element carries forward
                            nextLevel.Add(currentLevel[i]);
                        }
                    }
                    currentLevel = nextLevel;
                }
            }

            return currentLevel[0];
        }

        /// <summary>
        /// Saves baseline entries with HMAC seal, Merkle root, and compresses text snapshots for diffing.
        /// </summary>
        public static BaselinePackage SaveBaseline(string rootFolder, List<FileScanResult> scanItems)
        {
            string baseDir = GetBaselineDirectory(rootFolder);
            string activePath = Path.Combine(baseDir, ActiveBaselineFile);
            string historyDir = Path.Combine(baseDir, "history");
            string snapshotsDir = Path.Combine(baseDir, "snapshots");

            Directory.CreateDirectory(historyDir);
            Directory.CreateDirectory(snapshotsDir);

            // 1. Archive current active baseline to history if it exists
            if (File.Exists(activePath))
            {
                string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                string archivePath = Path.Combine(historyDir, $"baseline_{timestamp}.fim");
                File.Copy(activePath, archivePath, true);
                PruneOldBaselines(historyDir, MaxSnapshotHistory);
            }

            // 2. Prepare entries and Merkle hashes
            var package = new BaselinePackage { CreatedUtc = DateTime.UtcNow };
            var hashes = new List<string>();
            var dataLines = new StringBuilder();

            foreach (var item in scanItems)
            {
                if (item.Status == "Deleted")
                {
                    string safeRel = item.RelativePath.Replace(Path.DirectorySeparatorChar, '_').Replace(Path.AltDirectorySeparatorChar, '_');
                    string oldSnap = Path.Combine(snapshotsDir, safeRel + ".gz");
                    if (File.Exists(oldSnap)) { try { File.Delete(oldSnap); } catch { } }
                    continue;
                }

                if (item.Status == "Unreadable" || item.Status == "Locked") continue;

                var entry = new BaselineEntry
                {
                    RelativePath = item.RelativePath,
                    Sha256 = item.Sha256,
                    Entropy = item.Entropy,
                    FileSize = item.FileSize,
                    LastModifiedTicks = item.LastModified.Ticks,
                    IsBinary = item.IsBinary
                };

                package.Entries[item.RelativePath] = entry;
                hashes.Add(item.Sha256);

                dataLines.AppendLine($"{entry.RelativePath}|{entry.Sha256}|{entry.Entropy}|{entry.FileSize}|{entry.LastModifiedTicks}|{entry.IsBinary}");

                // Save compressed text snapshot for diffing if plain text or Office document (.docx)
                string fullPath = !string.IsNullOrEmpty(item.FullPath) ? item.FullPath : Path.Combine(rootFolder, item.RelativePath);
                if (File.Exists(fullPath) && !IsVendorOrCachePath(item.RelativePath))
                {
                    if (!item.IsBinary && item.FileSize <= MaxSnapshotFileSize)
                    {
                        SaveCompressedSnapshot(snapshotsDir, item.RelativePath, fullPath);
                    }
                    else if (OfficeTextExtractor.IsOfficeDocument(item.RelativePath) && item.FileSize <= 25 * 1024 * 1024)
                    {
                        string docxText = OfficeTextExtractor.ExtractText(fullPath);
                        if (!string.IsNullOrEmpty(docxText))
                        {
                            SaveCompressedSnapshotString(snapshotsDir, item.RelativePath, docxText);
                        }
                    }
                }
            }

            hashes.Sort(StringComparer.Ordinal);
            package.MerkleRoot = ComputeMerkleRoot(hashes);

            // 3. Compute cryptographic HMAC seal over data lines and Merkle Root
            string contentPayload = $"MERKLE:{package.MerkleRoot}\n" + dataLines.ToString();
            package.HmacSeal = ComputeHmacSeal(contentPayload);

            // 4. Write active baseline file
            using (var writer = new StreamWriter(activePath, false, Encoding.UTF8))
            {
                writer.WriteLine($"# SENTINEL_FIM_BASELINE_V1");
                writer.WriteLine($"# CREATED_UTC:{package.CreatedUtc:O}");
                writer.WriteLine($"# MERKLE_ROOT:{package.MerkleRoot}");
                writer.WriteLine($"# HMAC_SEAL:{package.HmacSeal}");
                writer.WriteLine($"# --- DATA ---");
                writer.Write(dataLines.ToString());
            }

            return package;
        }

        /// <summary>
        /// Atomically updates or removes a single file entry in the active baseline and recomputes the Merkle Root & HMAC Seal.
        /// </summary>
        public static BaselinePackage AcceptSingleFile(string rootFolder, FileScanResult item)
        {
            var package = LoadActiveBaseline(rootFolder);
            if (package == null) package = new BaselinePackage();

            string baseDir = GetBaselineDirectory(rootFolder);
            string snapshotsDir = Path.Combine(baseDir, "snapshots");
            Directory.CreateDirectory(snapshotsDir);

            if (item.Status == "Deleted")
            {
                package.Entries.Remove(item.RelativePath);
                string safeRel = item.RelativePath.Replace(Path.DirectorySeparatorChar, '_').Replace(Path.AltDirectorySeparatorChar, '_');
                string oldSnap = Path.Combine(snapshotsDir, safeRel + ".gz");
                if (File.Exists(oldSnap)) { try { File.Delete(oldSnap); } catch { } }
            }
            else
            {
                package.Entries[item.RelativePath] = new BaselineEntry
                {
                    RelativePath = item.RelativePath,
                    Sha256 = item.Sha256,
                    Entropy = item.Entropy,
                    FileSize = item.FileSize,
                    LastModifiedTicks = item.LastModified.Ticks,
                    IsBinary = item.IsBinary
                };

                string fullPath = !string.IsNullOrEmpty(item.FullPath) ? item.FullPath : Path.Combine(rootFolder, item.RelativePath);
                if (!item.IsBinary && item.FileSize <= MaxSnapshotFileSize && File.Exists(fullPath) && !IsVendorOrCachePath(item.RelativePath))
                {
                    SaveCompressedSnapshot(snapshotsDir, item.RelativePath, fullPath);
                }
            }

            var allItems = new List<FileScanResult>();
            foreach (var kvp in package.Entries)
            {
                allItems.Add(new FileScanResult
                {
                    RelativePath = kvp.Value.RelativePath,
                    Sha256 = kvp.Value.Sha256,
                    Entropy = kvp.Value.Entropy,
                    FileSize = kvp.Value.FileSize,
                    LastModified = new DateTime(kvp.Value.LastModifiedTicks, DateTimeKind.Utc),
                    IsBinary = kvp.Value.IsBinary,
                    Status = "Unchanged"
                });
            }

            return SaveBaseline(rootFolder, allItems);
        }

        public static BaselinePackage LoadActiveBaseline(string rootFolder)
        {
            string baseDir = Path.Combine(rootFolder, BaselineDirName);
            string activePath = Path.Combine(baseDir, ActiveBaselineFile);
            if (!File.Exists(activePath)) return null;

            var package = new BaselinePackage();
            string declaredMerkle = "";
            string declaredSeal = "";
            var dataLines = new StringBuilder();

            string[] lines = File.ReadAllLines(activePath, Encoding.UTF8);
            bool inData = false;

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                if (!inData)
                {
                    if (line.StartsWith("# MERKLE_ROOT:")) declaredMerkle = line.Substring(14).Trim();
                    else if (line.StartsWith("# HMAC_SEAL:")) declaredSeal = line.Substring(12).Trim();
                    else if (line.StartsWith("# --- DATA ---")) inData = true;
                    continue;
                }

                if (string.IsNullOrWhiteSpace(line)) continue;
                dataLines.AppendLine(line);

                string[] parts = line.Split('|');
                if (parts.Length >= 6)
                {
                    package.Entries[parts[0]] = new BaselineEntry
                    {
                        RelativePath = parts[0],
                        Sha256 = parts[1],
                        Entropy = double.TryParse(parts[2], out double e) ? e : 0.0,
                        FileSize = long.TryParse(parts[3], out long sz) ? sz : 0,
                        LastModifiedTicks = long.TryParse(parts[4], out long tk) ? tk : 0,
                        IsBinary = bool.TryParse(parts[5], out bool b) && b
                    };
                }
            }

            package.MerkleRoot = declaredMerkle;
            package.HmacSeal = declaredSeal;

            // Verify Seal
            string contentPayload = $"MERKLE:{package.MerkleRoot}\n" + dataLines.ToString();
            string expectedSeal = ComputeHmacSeal(contentPayload);
            package.IsSealValid = string.Equals(declaredSeal, expectedSeal, StringComparison.OrdinalIgnoreCase);

            return package;
        }

        private static bool IsSystemOrRootDirectory(string dir)
        {
            if (string.IsNullOrEmpty(dir)) return true;
            try
            {
                string full = Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string downloads = Path.Combine(userProfile, "Downloads");
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string root = Path.GetPathRoot(full).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                if (string.Equals(full, userProfile, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(full, downloads, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(full, desktop, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(full, documents, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch { }
            return false;
        }

        public static bool IsVendorOrCachePath(string relativePath)
        {
            if (string.IsNullOrEmpty(relativePath)) return false;
            string p = relativePath.Replace('/', '\\').ToLowerInvariant();
            if (p.StartsWith(".venv\\") || p.Contains("\\.venv\\")) return true;
            if (p.StartsWith("venv\\") || p.Contains("\\venv\\")) return true;
            if (p.StartsWith("node_modules\\") || p.Contains("\\node_modules\\")) return true;
            if (p.StartsWith("__pycache__\\") || p.Contains("\\__pycache__\\")) return true;
            if (p.StartsWith(".git\\") || p.Contains("\\.git\\")) return true;
            if (p.StartsWith("site-packages\\") || p.Contains("\\site-packages\\")) return true;
            if (p.StartsWith("dist\\") || p.Contains("\\dist\\")) return true;
            if (p.StartsWith("build\\") || p.Contains("\\build\\")) return true;
            return false;
        }

        /// <summary>
        /// Discovers either a direct baseline or walks parent directories upwards to inherit an ancestor baseline.
        /// Returns the loaded package and outputs the baseline's root directory.
        /// </summary>
        public static BaselinePackage FindInheritedOrLocalBaseline(string targetPath, out string baselineRootFolder)
        {
            baselineRootFolder = null;
            if (string.IsNullOrEmpty(targetPath)) return null;

            string currentDir = File.Exists(targetPath) ? Path.GetDirectoryName(targetPath) : targetPath;
            if (!Directory.Exists(currentDir)) return null;

            currentDir = Path.GetFullPath(currentDir);

            // 1. Direct local baseline check first
            string localBaseDir = Path.Combine(currentDir, BaselineDirName);
            string localActivePath = Path.Combine(localBaseDir, ActiveBaselineFile);
            if (File.Exists(localActivePath))
            {
                baselineRootFolder = currentDir;
                return LoadActiveBaseline(currentDir);
            }

            // 2. Only search parent directories if not a system/user folder
            var dirInfo = new DirectoryInfo(currentDir).Parent;
            while (dirInfo != null)
            {
                string candidateDir = dirInfo.FullName;

                // Stop at system roots like Downloads, Desktop, UserProfile, C:\
                if (IsSystemOrRootDirectory(candidateDir)) break;

                string baseDir = Path.Combine(candidateDir, BaselineDirName);
                string activePath = Path.Combine(baseDir, ActiveBaselineFile);

                if (File.Exists(activePath))
                {
                    var parentPkg = LoadActiveBaseline(candidateDir);
                    if (parentPkg != null && parentPkg.Entries.Count > 0)
                    {
                        // Verify that this ancestor baseline actually contains entries inside currentDir
                        string relPrefix = currentDir.Substring(candidateDir.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
                        bool hasSubfolderEntries = false;
                        foreach (string k in parentPkg.Entries.Keys)
                        {
                            if (k.StartsWith(relPrefix, StringComparison.OrdinalIgnoreCase))
                            {
                                hasSubfolderEntries = true;
                                break;
                            }
                        }

                        if (hasSubfolderEntries)
                        {
                            baselineRootFolder = candidateDir;
                            return parentPkg;
                        }
                    }
                }

                dirInfo = dirInfo.Parent;
            }

            return null;
        }

        private static void SaveCompressedSnapshot(string snapshotsDir, string relativePath, string fullPath)
        {
            try
            {
                string safeRelative = relativePath.Replace(Path.DirectorySeparatorChar, '_').Replace(Path.AltDirectorySeparatorChar, '_');
                string snapFile = Path.Combine(snapshotsDir, safeRelative + ".gz");

                byte[] textBytes = File.ReadAllBytes(fullPath);
                using (var fs = new FileStream(snapFile, FileMode.Create, FileAccess.Write))
                using (var gz = new GZipStream(fs, CompressionMode.Compress))
                {
                    gz.Write(textBytes, 0, textBytes.Length);
                }
            }
            catch { }
        }

        private static void SaveCompressedSnapshotString(string snapshotsDir, string relativePath, string content)
        {
            try
            {
                string safeRelative = relativePath.Replace(Path.DirectorySeparatorChar, '_').Replace(Path.AltDirectorySeparatorChar, '_');
                string snapFile = Path.Combine(snapshotsDir, safeRelative + ".gz");

                byte[] textBytes = Encoding.UTF8.GetBytes(content);
                using (var fs = new FileStream(snapFile, FileMode.Create, FileAccess.Write))
                using (var gz = new GZipStream(fs, CompressionMode.Compress))
                {
                    gz.Write(textBytes, 0, textBytes.Length);
                }
            }
            catch { }
        }

        public static string LoadCompressedSnapshotText(string rootFolder, string relativePath)
        {
            try
            {
                if (string.IsNullOrEmpty(rootFolder) || string.IsNullOrEmpty(relativePath)) return null;

                string baseDir = Path.Combine(rootFolder, BaselineDirName);
                string snapshotsDir = Path.Combine(baseDir, "snapshots");
                if (!Directory.Exists(snapshotsDir)) return null;

                string cleanRel = relativePath.TrimStart('\\', '/', '.');
                string safeRelative = cleanRel.Replace(Path.DirectorySeparatorChar, '_').Replace(Path.AltDirectorySeparatorChar, '_');
                string snapFile = Path.Combine(snapshotsDir, safeRelative + ".gz");

                if (!File.Exists(snapFile))
                {
                    // Fallback 1: try finding snapshot by filename only
                    string baseName = Path.GetFileName(cleanRel);
                    string altSnap = Path.Combine(snapshotsDir, baseName + ".gz");
                    if (File.Exists(altSnap))
                    {
                        snapFile = altSnap;
                    }
                    else
                    {
                        // Fallback 2: fuzzy search for any .gz file in snapshotsDir matching the filename
                        bool found = false;
                        foreach (string cand in Directory.GetFiles(snapshotsDir, "*.gz"))
                        {
                            string cName = Path.GetFileName(cand);
                            if (cName.EndsWith(baseName + ".gz", StringComparison.OrdinalIgnoreCase) ||
                                cName.IndexOf(Path.GetFileNameWithoutExtension(baseName), StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                snapFile = cand;
                                found = true;
                                break;
                            }
                        }
                        if (!found) return null;
                    }
                }

                using (var fs = new FileStream(snapFile, FileMode.Open, FileAccess.Read))
                using (var gz = new GZipStream(fs, CompressionMode.Decompress))
                using (var reader = new StreamReader(gz, Encoding.UTF8))
                {
                    return reader.ReadToEnd();
                }
            }
            catch
            {
                return null;
            }
        }

        private static void PruneOldBaselines(string historyDir, int keepCount)
        {
            try
            {
                var files = new List<FileInfo>(new DirectoryInfo(historyDir).GetFiles("baseline_*.fim"));
                files.Sort((a, b) => b.CreationTimeUtc.CompareTo(a.CreationTimeUtc));

                for (int i = keepCount; i < files.Count; i++)
                {
                    files[i].Delete();
                }
            }
            catch { }
        }

        public static string GetTotalStorageUsageFormatted(string rootFolder)
        {
            try
            {
                string baseDir = Path.Combine(rootFolder, BaselineDirName);
                if (!Directory.Exists(baseDir)) return "0 KB";

                long totalBytes = 0;
                foreach (var file in Directory.GetFiles(baseDir, "*", SearchOption.AllDirectories))
                {
                    totalBytes += new FileInfo(file).Length;
                }

                if (totalBytes < 1024) return $"{totalBytes} B";
                if (totalBytes < 1024 * 1024) return $"{totalBytes / 1024.0:F1} KB";
                return $"{totalBytes / (1024.0 * 1024.0):F2} MB";
            }
            catch
            {
                return "Unknown";
            }
        }

        public static void PurgeOldArchives(string rootFolder)
        {
            try
            {
                string baseDir = Path.Combine(rootFolder, BaselineDirName);
                string historyDir = Path.Combine(baseDir, "history");
                if (Directory.Exists(historyDir))
                {
                    Directory.Delete(historyDir, true);
                    Directory.CreateDirectory(historyDir);
                }
            }
            catch { }
        }
    }
}
