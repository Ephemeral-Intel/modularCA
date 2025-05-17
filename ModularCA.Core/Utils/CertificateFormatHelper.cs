using System.IO;

namespace ModularCA.Core.Utils;

public static class CertificateFormatHelper
{
    public static bool IsPemFile(string path)
    {
        try
        {
            var firstLine = File.ReadLines(path).FirstOrDefault()?.Trim();
            return firstLine != null && firstLine.StartsWith("-----BEGIN");
        }
        catch
        {
            return false; // Invalid or unreadable file
        }
    }

    public static bool IsPfxFile(string path)
    {
        return Path.GetExtension(path).Equals(".pfx", StringComparison.OrdinalIgnoreCase);
    }
}
