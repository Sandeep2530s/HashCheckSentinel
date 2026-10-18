using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HashCheckSentinel.Core
{
    public sealed class FileScanResult
    {
        public string RelativePath { get; set; }
        public string FullPath { get; set; }
        public string Status { get; set; } = "Unchanged"; // Unchanged, Modified, Added, Deleted, Threat, Locked, Unreadable
        public string Sha256 { get; set; }
        public double Entropy { get; set; }
        public long FileSize { get; set; }
        public bool IsBinary { get; set; }
        public string MagicType { get; set; }
        public string ThreatReason { get; set; }
        public DateTime LastModified { get; set; }
    }

    public sealed class ScanProgress
    {
        public int ProcessedCount { get; set; }
        public int TotalCount { get; set; }
        public string CurrentFile { get; set; }
        public double ThroughputMBps { get; set; }
    }

    public static class Hasher
    {
        private const int BufferSize = 65536; // 64 KB streaming buffer

        public static string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            try
            {
                string full = Path.GetFullPath(path);
                if (full.Length >= 240 && !full.StartsWith(@"\\?\") && !full.StartsWith(@"\\"))
                {
                    return @"\\?\" + full;
                }
                return full;
            }
            catch
            {
                return path;
            }
        }

        private static FileStream OpenFileWithRetry(string safePath, int maxRetries = 6, int delayMs = 75)
        {
            for (int i = 0; i < maxRetries; i++)
            {
                try
                {
                    return new FileStream(safePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, BufferSize);
                }
                catch (IOException)
                {
                    if (i == maxRetries - 1) throw;
                    Thread.Sleep(delayMs);
                }
                catch (UnauthorizedAccessException)
                {
                    if (i == maxRetries - 1) throw;
                    Thread.Sleep(delayMs);
                }
            }
            return new FileStream(safePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, BufferSize);
        }

        public static string ComputeFileSha256(string filePath)
        {
            string safe = NormalizePath(filePath);
            using (var sha = SHA256.Create())
            using (var stream = OpenFileWithRetry(safe))
            {
                byte[] hash = sha.ComputeHash(stream);
                var sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++)
                {
                    sb.Append(hash[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Safely enumerates all accessible files in a directory tree without crashing on protected subfolders.
        /// </summary>
        public static List<string> SafeEnumerateFiles(string rootDirectory)
        {
            var result = new List<string>();
            var queue = new Queue<string>();
            queue.Enqueue(rootDirectory);

            while (queue.Count > 0)
            {
                string currentDir = queue.Dequeue();
                try
                {
                    foreach (string file in Directory.GetFiles(currentDir))
                    {
                        if (file.IndexOf(".sentinel-baseline", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                        result.Add(file);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (DirectoryNotFoundException) { }
                catch (IOException) { }

                try
                {
                    foreach (string subDir in Directory.GetDirectories(currentDir))
                    {
                        string dirName = Path.GetFileName(subDir);
                        if (string.Equals(dirName, ".sentinel-baseline", StringComparison.OrdinalIgnoreCase)) continue;
                        if (string.Equals(dirName, ".git", StringComparison.OrdinalIgnoreCase)) continue;
                        queue.Enqueue(subDir);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (DirectoryNotFoundException) { }
                catch (IOException) { }
            }

            return result;
        }

        /// <summary>
        /// Reads file once and computes SHA-256, Shannon entropy, binary check, and magic signature in a single pass.
        /// </summary>
        public static void AnalyzeFileSinglePass(string filePath, out string sha256, out double entropy, out bool isBinary, out string magicType)
        {
            string safe = NormalizePath(filePath);
            using (var sha = SHA256.Create())
            using (var stream = OpenFileWithRetry(safe))
            {
                long length = stream.Length;
                byte[] buffer = new byte[BufferSize];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);

                if (bytesRead == 0)
                {
                    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
                    entropy = 0.0;
                    isBinary = false;
                    magicType = "Empty File";
                    return;
                }

                magicType = "Plain Text / Script";
                if (bytesRead >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A) magicType = "Executable (PE/MZ)";
                else if (bytesRead >= 4 && buffer[0] == 0x25 && buffer[1] == 0x50 && buffer[2] == 0x44 && buffer[3] == 0x46) magicType = "PDF Document";
                else if (bytesRead >= 4 && buffer[0] == 0x50 && buffer[1] == 0x4B && (buffer[2] == 0x03 || buffer[2] == 0x05)) magicType = "ZIP/Archive/Office";
                else if (bytesRead >= 3 && buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF) magicType = "JPEG Image";
                else if (bytesRead >= 4 && buffer[0] == 0x89 && buffer[1] == 0x50 && buffer[2] == 0x4E && buffer[3] == 0x47) magicType = "PNG Image";

                isBinary = false;
                int checkLen = Math.Min(bytesRead, 4096);
                for (int i = 0; i < checkLen; i++)
                {
                    if (buffer[i] == 0)
                    {
                        isBinary = true;
                        if (magicType == "Plain Text / Script") magicType = "Binary Data";
                        break;
                    }
                }

                int[] frequencies = new int[256];
                for (int i = 0; i < bytesRead; i++)
                {
                    frequencies[buffer[i]]++;
                }

                double ent = 0.0;
                double len = bytesRead;
                for (int i = 0; i < 256; i++)
                {
                    if (frequencies[i] > 0)
                    {
                        double p = frequencies[i] / len;
                        ent -= p * (Math.Log(p) / Math.Log(2.0));
                    }
                }
                entropy = Math.Round(ent, 2);

                if (bytesRead < buffer.Length || stream.Position >= length)
                {
                    sha.TransformFinalBlock(buffer, 0, bytesRead);
                }
                else
                {
                    sha.TransformBlock(buffer, 0, bytesRead, null, 0);
                    while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        sha.TransformBlock(buffer, 0, bytesRead, null, 0);
                    }
                    sha.TransformFinalBlock(buffer, 0, 0);
                }

                byte[] hash = sha.Hash;
                var sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                sha256 = sb.ToString();
            }
        }

        /// <summary>
        /// Scans a directory in parallel across all CPU cores with streaming 64 KB buffers.
        /// </summary>
        public static List<FileScanResult> ScanDirectoryParallel(
            string rootDirectory,
            Action<ScanProgress> progressCallback = null,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            string root = Path.GetFullPath(rootDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            List<string> allFiles = SafeEnumerateFiles(root);
            int totalCount = allFiles.Count;
            int processed = 0;
            long totalBytesHashed = 0;
            var startTime = DateTime.UtcNow;

            var results = new ConcurrentBag<FileScanResult>();

            var options = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount,
                CancellationToken = cancellationToken
            };

            try
            {
                Parallel.ForEach(allFiles, options, file =>
                {
                    options.CancellationToken.ThrowIfCancellationRequested();

                    string relative = file.Substring(root.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    var item = new FileScanResult
                    {
                        RelativePath = relative,
                        FullPath = file
                    };

                    try
                    {
                        var info = new FileInfo(file);
                        item.FileSize = info.Length;
                        item.LastModified = info.LastWriteTimeUtc;

                        string sha;
                        double ent;
                        bool bin;
                        string magic;
                        AnalyzeFileSinglePass(file, out sha, out ent, out bin, out magic);

                        item.Sha256 = sha;
                        item.Entropy = ent;
                        item.IsBinary = bin;
                        item.MagicType = magic;

                        // Steganography check for PNG
                        long trailing;
                        if (file.EndsWith(".png", StringComparison.OrdinalIgnoreCase) &&
                            EntropyCalculator.DetectPngSteganography(file, out trailing))
                        {
                            item.ThreatReason = $"Steganography: {trailing} trailing bytes past PNG end marker";
                        }
                        else if (item.Entropy >= 7.90 && item.FileSize > 512 && !file.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && !file.EndsWith(".rar", StringComparison.OrdinalIgnoreCase))
                        {
                            item.ThreatReason = $"High Entropy ({item.Entropy}/8.0): Possible encryption/ransomware";
                        }

                        Interlocked.Add(ref totalBytesHashed, item.FileSize);
                    }
                        catch (UnauthorizedAccessException)
                        {
                            item.Status = "Unreadable";
                            item.Sha256 = "—";
                            item.MagicType = "Access Denied";
                        }
                        catch (IOException)
                        {
                            item.Status = "Locked";
                            item.Sha256 = "—";
                            item.MagicType = "File In-Use / Locked";
                        }
                        catch (Exception ex)
                        {
                            item.Status = "Unreadable";
                            item.Sha256 = "—";
                            item.MagicType = ex.GetType().Name;
                        }

                        results.Add(item);

                        int currentProcessed = Interlocked.Increment(ref processed);
                        if (progressCallback != null && (currentProcessed % 150 == 0 || currentProcessed == totalCount))
                        {
                            double elapsedSec = Math.Max(0.01, (DateTime.UtcNow - startTime).TotalSeconds);
                            double mbps = (totalBytesHashed / (1024.0 * 1024.0)) / elapsedSec;

                            progressCallback(new ScanProgress
                            {
                                ProcessedCount = currentProcessed,
                                TotalCount = totalCount,
                                CurrentFile = relative,
                                ThroughputMBps = Math.Round(mbps, 1)
                            });
                        }
                    });
                }
                catch (OperationCanceledException)
                {
                    // Scan cancelled by user
                }

                return new List<FileScanResult>(results);
        }
    }
}
