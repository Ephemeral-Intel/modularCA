using Org.BouncyCastle.X509;
using Org.BouncyCastle.OpenSsl;

namespace ModularCA.Core.Utils;

public static class TrustStoreLoader
{
    public static IList<X509Certificate> LoadTrustStore(string path)
    {
        var certs = new List<X509Certificate>();

        using var reader = File.OpenText(path);
        var pemReader = new PemReader(reader);

        object? obj;
        while ((obj = pemReader.ReadObject()) != null)
        {
            if (obj is X509Certificate cert)
            {
                certs.Add(cert);
            }
        }

        return certs;
    }
}
