using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System.Text;
using ModularCA.Core.Models;


namespace ModularCA.Core.Utils;

public static class CertExportUtil
{
    // Export cert to PEM
    public static string ExportCertAsPem(X509Certificate cert)
    {
        using var sw = new StringWriter();
        var pemWriter = new PemWriter(sw);
        pemWriter.WriteObject(cert);
        pemWriter.Writer.Flush();
        return sw.ToString();
    }

    // Export private key and cert as PKCS#12 (.pfx)
    public static byte[] ExportPkcs12(
    string friendlyName,
    Org.BouncyCastle.X509.X509Certificate leafCert,
    AsymmetricKeyParameter privateKey,
    IEnumerable<Org.BouncyCastle.X509.X509Certificate>? chain,
    string password)
    {
        var store = new Pkcs12StoreBuilder().Build();

        // Build chain entries (leaf first, intermediates after)
        var certChain = new List<X509CertificateEntry>
    {
        new X509CertificateEntry(leafCert)
    };

        if (chain != null)
        {
            certChain.AddRange(chain.Select(c => new X509CertificateEntry(c)));
        }

        store.SetKeyEntry(friendlyName,
            new AsymmetricKeyEntry(privateKey),
            certChain.ToArray());

        using var ms = new MemoryStream();
        store.Save(ms, password.ToCharArray(), new SecureRandom());
        return ms.ToArray();
    }

    public static string ExportPemChain(
    Org.BouncyCastle.X509.X509Certificate leafCert,
    IEnumerable<Org.BouncyCastle.X509.X509Certificate>? chain)
    {
        var sb = new StringBuilder();

        using var sw = new StringWriter(sb);
        var writer = new PemWriter(sw);

        writer.WriteObject(leafCert);

        if (chain != null)
        {
            foreach (var cert in chain)
            {
                writer.WriteObject(cert);
            }
        }

        writer.Writer.Flush();
        return sb.ToString();
    }

    public static byte[] ExportCertificateFlexible(
    Org.BouncyCastle.X509.X509Certificate cert,
    AsymmetricKeyParameter? privateKey,
    CertificateExportOptions options)
    {
        switch (options.Format.ToLowerInvariant())
        {
            case "pem":
                var pem = ExportPemChain(cert, options.Chain);
                return Encoding.UTF8.GetBytes(pem);

            case "der":
                return ExportDer(cert);

            case "pfx":
                if (!options.IncludePrivateKey || privateKey == null)
                    throw new InvalidOperationException("Private key required for PFX export.");

                if (string.IsNullOrWhiteSpace(options.Password))
                    throw new InvalidOperationException("Password required for PFX export.");

                return ExportPkcs12(
                    options.FriendlyName ?? "certificate",
                    cert,
                    privateKey,
                    options.Chain,
                    options.Password);

            default:
                throw new InvalidOperationException("Unsupported export format: " + options.Format);
        }
    }


    // Export DER (.cer) - already built-in
    public static byte[] ExportDer(X509Certificate cert) => cert.GetEncoded();

}
