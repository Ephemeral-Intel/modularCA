using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using ModularCA.Core.Models;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text.Json;
using System.Security.Cryptography;

namespace ModularCA.Core.Utils;

public static class CertParseUtil
{
    public static CertificateInfoModel ParseCertificate(X509Certificate cert)
    {
        var info = new CertificateInfoModel
        {      

        SubjectDN = cert.SubjectDN.ToString(),
            Issuer = cert.IssuerDN.ToString(),
            SerialNumber = cert.SerialNumber.ToString(16).ToUpperInvariant(),
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprints = cert.GetFingerprint() // We'll add this next
        };

        // Basic Constraints
        var bc = cert.GetExtensionValue(X509Extensions.BasicConstraints);
        if (bc != null)
        {
            var constraints = BasicConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(bc));
            info.IsCA = constraints.IsCA();
        }

        // Key Usage
        var kuExt = cert.GetExtensionValue(X509Extensions.KeyUsage);
        if (kuExt != null)
        {
            var keyUsage = KeyUsage.GetInstance(X509ExtensionUtilities.FromExtensionValue(kuExt));
            var usages = new[]
            {
                (KeyUsage.DigitalSignature, "DigitalSignature"),
                (KeyUsage.NonRepudiation, "NonRepudiation"),
                (KeyUsage.KeyEncipherment, "KeyEncipherment"),
                (KeyUsage.DataEncipherment, "DataEncipherment"),
                (KeyUsage.KeyAgreement, "KeyAgreement"),
                (KeyUsage.KeyCertSign, "KeyCertSign"),
                (KeyUsage.CrlSign, "CrlSign")
            };

            foreach (var (flag, name) in usages)
                if ((keyUsage.IntValue & flag) != 0)
                    info.KeyUsages.Add(name);
        }

        // Extended Key Usage
        var ekuExt = cert.GetExtensionValue(X509Extensions.ExtendedKeyUsage);
        if (ekuExt != null)
        {
            var eku = ExtendedKeyUsage.GetInstance(X509ExtensionUtilities.FromExtensionValue(ekuExt));
            info.ExtendedKeyUsages = eku.GetAllUsages().Cast<DerObjectIdentifier>().Select(x => x.Id).ToList();
        }

        // SAN
        var sanExt = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
        if (sanExt != null)
        {
            var san = Asn1Sequence.GetInstance(X509ExtensionUtilities.FromExtensionValue(sanExt));
            foreach (Asn1Encodable entry in san)
            {
                var gn = GeneralName.GetInstance(entry);
                info.SubjectAlternativeNames.Add($"{GeneralNameTypeName(gn.TagNo)}:{gn.Name}");
            }
        }

        return info;
    }

    private static string GeneralNameTypeName(int tag)
    {
        return tag switch
        {
            GeneralName.DnsName => "DNS",
            GeneralName.IPAddress => "IP",
            GeneralName.Rfc822Name => "Email",
            _ => "Other"
        };
    }

    private static string GetFingerprint(this X509Certificate cert)
    {
        byte[] sysBytePublicKey = cert.GetEncoded();
        byte[] sysSha256hash = SHA256.HashData(sysBytePublicKey);

        string sysSha256Thumbprint = BitConverter.ToString(sysSha256hash).Replace("-", "").ToUpperInvariant();
        Console.WriteLine("SHA 256 Thumbprint: " + sysSha256Thumbprint);
        
        byte[] sysSha1hash = SHA1.HashData(sysBytePublicKey);
        string sysSha1Thumbprint = BitConverter.ToString(sysSha1hash).Replace("-", "").ToUpperInvariant();
        Console.WriteLine("SHA 1 Thumbprint: " + sysSha1Thumbprint);

        var sysThumbprintDict = new Dictionary<string, string>
{
    { "SHA 1", sysSha1Thumbprint },
    { "SHA 256", sysSha256Thumbprint }
};

        string sysThumbprints = JsonSerializer.Serialize(sysThumbprintDict);

        return sysThumbprints;
    }

}
