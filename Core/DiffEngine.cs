using System;
using System.Collections.Generic;
using System.IO;

namespace HashCheckSentinel.Core
{
    public enum DiffType
    {
        Unchanged,
        Added,
        Deleted
    }

    public sealed class DiffLine
    {
        public DiffType Type { get; set; }
        public int? OldLineNumber { get; set; }
        public int? NewLineNumber { get; set; }
        public string Text { get; set; }
    }

    public sealed class DiffReport
    {
        public List<DiffLine> Lines { get; set; } = new List<DiffLine>();
        public int AddedCount { get; set; }
        public int DeletedCount { get; set; }
        public int UnchangedCount { get; set; }
    }

    public sealed class BinaryDeltaReport
    {
        public string RelativePath { get; set; }
        public long OldSize { get; set; }
        public long NewSize { get; set; }
        public long SizeDelta => NewSize - OldSize;
        public double OldEntropy { get; set; }
        public double NewEntropy { get; set; }
        public double EntropyDelta => Math.Round(NewEntropy - OldEntropy, 2);
        public string OldSha256 { get; set; }
        public string NewSha256 { get; set; }
        public bool TimestompingDetected { get; set; }
        public string Assessment { get; set; }
    }

    public static class DiffEngine
    {
        /// <summary>
        /// Computes line-by-line diff using the classic Longest Common Subsequence (LCS) Dynamic Programming algorithm.
        /// </summary>
        public static DiffReport ComputeTextDiff(string oldText, string newText)
        {
            var report = new DiffReport();
            string[] oldLines = (oldText ?? "").Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            string[] newLines = (newText ?? "").Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            int n = oldLines.Length;
            int m = newLines.Length;

            // Cap matrix size to avoid excessive memory on giant files (>2000 lines uses fast chunked diff)
            if (n > 2500 || m > 2500)
            {
                return FastChunkDiff(oldLines, newLines);
            }

            int[,] lcs = new int[n + 1, m + 1];

            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    if (string.Equals(oldLines[i], newLines[j], StringComparison.Ordinal))
                    {
                        lcs[i + 1, j + 1] = lcs[i, j] + 1;
                    }
                    else
                    {
                        lcs[i + 1, j + 1] = Math.Max(lcs[i + 1, j], lcs[i, j + 1]);
                    }
                }
            }

            var resultStack = new Stack<DiffLine>();
            int rI = n;
            int rJ = m;

            while (rI > 0 || rJ > 0)
            {
                if (rI > 0 && rJ > 0 && string.Equals(oldLines[rI - 1], newLines[rJ - 1], StringComparison.Ordinal))
                {
                    resultStack.Push(new DiffLine
                    {
                        Type = DiffType.Unchanged,
                        OldLineNumber = rI,
                        NewLineNumber = rJ,
                        Text = oldLines[rI - 1]
                    });
                    rI--;
                    rJ--;
                }
                else if (rJ > 0 && (rI == 0 || lcs[rI, rJ - 1] >= lcs[rI - 1, rJ]))
                {
                    resultStack.Push(new DiffLine
                    {
                        Type = DiffType.Added,
                        OldLineNumber = null,
                        NewLineNumber = rJ,
                        Text = newLines[rJ - 1]
                    });
                    rJ--;
                }
                else if (rI > 0 && (rJ == 0 || lcs[rI, rJ - 1] < lcs[rI - 1, rJ]))
                {
                    resultStack.Push(new DiffLine
                    {
                        Type = DiffType.Deleted,
                        OldLineNumber = rI,
                        NewLineNumber = null,
                        Text = oldLines[rI - 1]
                    });
                    rI--;
                }
            }

            while (resultStack.Count > 0)
            {
                var line = resultStack.Pop();
                report.Lines.Add(line);
                if (line.Type == DiffType.Added) report.AddedCount++;
                else if (line.Type == DiffType.Deleted) report.DeletedCount++;
                else report.UnchangedCount++;
            }

            return report;
        }

        private static DiffReport FastChunkDiff(string[] oldLines, string[] newLines)
        {
            var report = new DiffReport();
            int max = Math.Max(oldLines.Length, newLines.Length);

            for (int i = 0; i < max; i++)
            {
                string oldL = i < oldLines.Length ? oldLines[i] : null;
                string newL = i < newLines.Length ? newLines[i] : null;

                if (oldL != null && newL != null)
                {
                    if (string.Equals(oldL, newL, StringComparison.Ordinal))
                    {
                        report.Lines.Add(new DiffLine { Type = DiffType.Unchanged, OldLineNumber = i + 1, NewLineNumber = i + 1, Text = oldL });
                        report.UnchangedCount++;
                    }
                    else
                    {
                        report.Lines.Add(new DiffLine { Type = DiffType.Deleted, OldLineNumber = i + 1, NewLineNumber = null, Text = oldL });
                        report.Lines.Add(new DiffLine { Type = DiffType.Added, OldLineNumber = null, NewLineNumber = i + 1, Text = newL });
                        report.DeletedCount++;
                        report.AddedCount++;
                    }
                }
                else if (oldL != null)
                {
                    report.Lines.Add(new DiffLine { Type = DiffType.Deleted, OldLineNumber = i + 1, NewLineNumber = null, Text = oldL });
                    report.DeletedCount++;
                }
                else if (newL != null)
                {
                    report.Lines.Add(new DiffLine { Type = DiffType.Added, OldLineNumber = null, NewLineNumber = i + 1, Text = newL });
                    report.AddedCount++;
                }
            }

            return report;
        }

        public static BinaryDeltaReport InspectBinaryDelta(
            string relativePath,
            BaselineEntry oldEntry,
            FileScanResult newResult)
        {
            var report = new BinaryDeltaReport
            {
                RelativePath = relativePath,
                OldSize = oldEntry != null ? oldEntry.FileSize : 0,
                NewSize = newResult.FileSize,
                OldEntropy = oldEntry != null ? oldEntry.Entropy : 0.0,
                NewEntropy = newResult.Entropy,
                OldSha256 = oldEntry != null ? oldEntry.Sha256 : "—",
                NewSha256 = newResult.Sha256
            };

            // Timestomp check: if hash changed but modification timestamp is older than or equal to baseline
            if (oldEntry != null && oldEntry.Sha256 != newResult.Sha256 &&
                newResult.LastModified.Ticks <= oldEntry.LastModifiedTicks)
            {
                report.TimestompingDetected = true;
            }

            if (report.EntropyDelta > 1.5 && report.NewEntropy >= 7.85)
            {
                report.Assessment = "CRITICAL: Entropy surge detected (+ " + report.EntropyDelta + "). Probable payload encryption or packing.";
            }
            else if (report.TimestompingDetected)
            {
                report.Assessment = "SUSPICIOUS: Timestomping detected. File content modified, but file timestamp rolled back.";
            }
            else if (OfficeTextExtractor.IsOfficeDocument(relativePath))
            {
                report.Assessment = $"Microsoft Office Document altered: OpenXML package re-compressed. Size delta: {(report.SizeDelta >= 0 ? "+" : "")}{report.SizeDelta:N0} bytes, Entropy: {report.OldEntropy:F2} -> {report.NewEntropy:F2}.";
            }
            else if (Math.Abs(report.SizeDelta) > 0)
            {
                report.Assessment = $"Standard binary alteration: Size changed by {(report.SizeDelta > 0 ? "+" : "")}{report.SizeDelta:N0} bytes.";
            }
            else
            {
                report.Assessment = "In-place byte modification with preserved file length.";
            }

            return report;
        }
    }
}
