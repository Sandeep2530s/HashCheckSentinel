using System;
using System.IO;
using System.IO.Packaging;
using System.Text;
using System.Xml;

namespace HashCheckSentinel.Core
{
    /// <summary>
    /// High-performance, zero-external-dependency OpenXML text extractor for Microsoft Office documents (.docx).
    /// Leverages WindowsBase System.IO.Packaging to extract text runs from word/document.xml.
    /// </summary>
    public static class OfficeTextExtractor
    {
        public static bool IsOfficeDocument(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string ext = Path.GetExtension(path);
            return string.Equals(ext, ".docx", StringComparison.OrdinalIgnoreCase)
                || string.Equals(ext, ".docm", StringComparison.OrdinalIgnoreCase)
                || string.Equals(ext, ".dotx", StringComparison.OrdinalIgnoreCase);
        }

        public static string ExtractText(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return null;

            try
            {
                // Open with ReadWrite share so file can be inspected even if open in Microsoft Word
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var pkg = Package.Open(stream, FileMode.Open, FileAccess.Read))
                {
                    var partUri = PackUriHelper.CreatePartUri(new Uri("/word/document.xml", UriKind.Relative));
                    if (!pkg.PartExists(partUri)) return null;

                    var part = pkg.GetPart(partUri);
                    using (var partStream = part.GetStream())
                    using (var reader = new StreamReader(partStream, Encoding.UTF8))
                    {
                        string xml = reader.ReadToEnd();
                        var doc = new XmlDocument();
                        doc.LoadXml(xml);

                        var ns = new XmlNamespaceManager(doc.NameTable);
                        ns.AddNamespace("w", "http://schemas.openxmlformats.org/wordprocessingml/2006/main");

                        var paras = doc.SelectNodes("//w:p", ns);
                        if (paras == null || paras.Count == 0) return null;

                        var sb = new StringBuilder();
                        foreach (XmlNode p in paras)
                        {
                            var texts = p.SelectNodes(".//w:t", ns);
                            if (texts == null || texts.Count == 0) continue;

                            var lineBuilder = new StringBuilder();
                            foreach (XmlNode t in texts)
                            {
                                lineBuilder.Append(t.InnerText);
                            }

                            string line = lineBuilder.ToString().Trim();
                            if (line.Length > 0)
                            {
                                sb.AppendLine(line);
                            }
                        }

                        return sb.Length > 0 ? sb.ToString() : null;
                    }
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
