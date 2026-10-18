using System;
using System.IO;

namespace HashCheckSentinel.Core
{
    public static class EntropyCalculator
    {
        /// <summary>
        /// Calculates Claude Shannon's Information Entropy for a byte stream.
        /// Range: 0.0 (all bytes identical) to 8.0 (pure uniform randomness, e.g., encrypted).
        /// </summary>
        public static double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0.0;

            int[] frequencies = new int[256];
            for (int i = 0; i < data.Length; i++)
            {
                frequencies[data[i]]++;
            }

            double entropy = 0.0;
            double len = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double p = frequencies[i] / len;
                    entropy -= p * (Math.Log(p) / Math.Log(2.0));
                }
            }

            return Math.Round(entropy, 2);
        }

        /// <summary>
        /// Calculates Shannon entropy from a file path using a memory-efficient sample (up to 256 KB).
        /// </summary>
        public static double CalculateFileEntropy(string filePath)
        {
            try
            {
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    int sampleSize = (int)Math.Min(stream.Length, 256 * 1024);
                    if (sampleSize == 0) return 0.0;

                    byte[] buffer = new byte[sampleSize];
                    int bytesRead = stream.Read(buffer, 0, sampleSize);
                    if (bytesRead < sampleSize)
                    {
                        byte[] trimmed = new byte[bytesRead];
                        Array.Copy(buffer, trimmed, bytesRead);
                        buffer = trimmed;
                    }
                    return CalculateEntropy(buffer);
                }
            }
            catch
            {
                return 0.0;
            }
        }

        /// <summary>
        /// Detects if file is likely plain text vs binary machine data.
        /// </summary>
        public static bool IsBinaryFile(string filePath)
        {
            try
            {
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    int checkSize = (int)Math.Min(stream.Length, 4096);
                    byte[] buffer = new byte[checkSize];
                    int read = stream.Read(buffer, 0, checkSize);

                    for (int i = 0; i < read; i++)
                    {
                        byte b = buffer[i];
                        // Null byte is a strong indicator of binary data
                        if (b == 0) return true;
                    }
                    return false;
                }
            }
            catch
            {
                return true;
            }
        }

        /// <summary>
        /// Detects file magic header format.
        /// </summary>
        public static string DetectMagicType(string filePath)
        {
            try
            {
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (stream.Length < 4) return "Unknown";
                    byte[] header = new byte[8];
                    int read = stream.Read(header, 0, 8);

                    if (read >= 2 && header[0] == 0x4D && header[1] == 0x5A) return "Executable (PE/MZ)";
                    if (read >= 4 && header[0] == 0x25 && header[1] == 0x50 && header[2] == 0x44 && header[3] == 0x46) return "PDF Document";
                    if (read >= 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04) return "ZIP/Archive/Office";
                    if (read >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF) return "JPEG Image";
                    if (read >= 4 && header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47) return "PNG Image";

                    return IsBinaryFile(filePath) ? "Binary Data" : "Plain Text / Script";
                }
            }
            catch
            {
                return "Inaccessible";
            }
        }

        /// <summary>
        /// Inspects PNG for appended data after IEND chunk (Steganography detection).
        /// </summary>
        public static bool DetectPngSteganography(string filePath, out long trailingBytes)
        {
            trailingBytes = 0;
            try
            {
                byte[] allBytes = File.ReadAllBytes(filePath);
                if (allBytes.Length < 8) return false;

                // Look for IEND chunk signature (49 45 4E 44)
                byte[] iend = new byte[] { 0x49, 0x45, 0x4E, 0x44 };
                for (int i = 0; i <= allBytes.Length - 8; i++)
                {
                    if (allBytes[i] == iend[0] && allBytes[i + 1] == iend[1] &&
                        allBytes[i + 2] == iend[2] && allBytes[i + 3] == iend[3])
                    {
                        // IEND chunk is 4 bytes length (0) + 4 bytes "IEND" + 4 bytes CRC
                        int endOfPng = i + 4 + 4; // after CRC
                        if (allBytes.Length > endOfPng + 16)
                        {
                            trailingBytes = allBytes.Length - endOfPng;
                            return true;
                        }
                        break;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
