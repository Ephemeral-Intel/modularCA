using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ModularCA.Core.Models;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Entities;


namespace ModularCA.Core.Utils;

public static class CertificateUtil
{
    // === Export to PEM ===
    public static string ExportCertificateToPem(X509Certificate cert)
    {
        using var sw = new StringWriter();
        var pemWriter = new PemWriter(sw);
        pemWriter.WriteObject(cert);
        return sw.ToString();
    }

    public static string ExportPrivateKeyToPem(AsymmetricKeyParameter privateKey)
    {
        using var sw = new StringWriter();
        var pemWriter = new PemWriter(sw);
        pemWriter.WriteObject(privateKey);
        return sw.ToString();
    }

    // === Parse Certificate ===
    public static CertificateInfoModel ParseCertificate(X509Certificate cert)
    {
        var info = new CertificateInfoModel
        {
            SubjectDN = cert.SubjectDN.ToString(),
            Issuer = cert.IssuerDN.ToString(),
            SerialNumber = cert.SerialNumber.ToString(16).ToUpperInvariant(),
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprints = GetThumbprints(cert)
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

    // === Thumbprint Calculation ===
    public static string GetThumbprints(X509Certificate cert)
    {
        byte[] certBytes = cert.GetEncoded();
        byte[] sha1 = SHA1.HashData(certBytes);
        byte[] sha256 = SHA256.HashData(certBytes);

        var dict = new Dictionary<string, string>
        {
            { "SHA 1", BitConverter.ToString(sha1).Replace("-", "").ToUpperInvariant() },
            { "SHA 256", BitConverter.ToString(sha256).Replace("-", "").ToUpperInvariant() }
        };
        return JsonSerializer.Serialize(dict);
    }

    // === Format Helpers ===
    public static bool IsPemFormat(string input)
    {
        return input.Contains("-----BEGIN CERTIFICATE-----");
    }

    public static X509Certificate ParseFromPem(string pem)
    {
        using var sr = new StringReader(pem);
        var pemReader = new PemReader(sr);
        return pemReader.ReadObject() as X509Certificate
            ?? throw new InvalidOperationException("Invalid PEM certificate.");
    }

    public class ParsedCsrInfo
    {
        public string SubjectName { get; set; } = string.Empty;
        public List<string> SubjectAlternativeNames { get; set; } = new();
        public string KeyAlgorithm { get; set; } = string.Empty;
        public string SignatureAlgorithm { get; set; } = string.Empty;
        public string KeySize { get; set; } = string.Empty;
    }

    public static ParsedCsrInfo ParseCsr(string pem)
    {
        using var sr = new StringReader(pem);
        var pemReader = new PemReader(sr);
        var csr = pemReader.ReadObject() as Pkcs10CertificationRequest
            ?? throw new InvalidOperationException("Invalid PEM CSR.");

        var info = csr.GetCertificationRequestInfo();

        // Subject
        var subject = info.Subject.ToString();

        // Key Algorithm & Size
        var pubKey = PublicKeyFactory.CreateKey(info.SubjectPublicKeyInfo);
        string keyAlgorithm = pubKey switch
        {
            Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters => "RSA",
            Org.BouncyCastle.Crypto.Parameters.ECKeyParameters => "EC",
            Org.BouncyCastle.Crypto.Parameters.DsaPublicKeyParameters => "DSA",
            _ => "Unknown"
        };
        string keySize = "";
        if (pubKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsa)
            keySize = rsa.Modulus.BitLength.ToString();
        else if (pubKey is Org.BouncyCastle.Crypto.Parameters.ECKeyParameters ec)
            keySize = ec.PublicKeyParamSet?.Id ?? "EC";

        // Signature Algorithm
        string sigAlg = csr.SignatureAlgorithm.Algorithm.Id;

        // SANs
        var altNames = new List<string>();
        var attrs = info.Attributes;
        foreach (var attrObj in attrs)
        {
            var attr = Org.BouncyCastle.Asn1.X509.AttributeX509.GetInstance(attrObj);
            if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
            {
                var extensions = X509Extensions.GetInstance(attr.AttrValues[0]);
                var sanExt = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
                if (sanExt != null)
                {
                    var sanSeq = Asn1Sequence.GetInstance(sanExt.GetParsedValue());
                    foreach (Asn1Encodable entry in sanSeq)
                    {
                        var gn = GeneralName.GetInstance(entry);
                        altNames.Add($"{GeneralNameTypeNameForCsr(gn.TagNo)}:{gn.Name}");
                    }
                }
            }
        }

        return new ParsedCsrInfo
        {
            SubjectName = subject,
            SubjectAlternativeNames = altNames,
            KeyAlgorithm = keyAlgorithm,
            SignatureAlgorithm = sigAlg,
            KeySize = keySize
        };
    }

    // Helper to avoid ambiguous call
    private static string GeneralNameTypeNameForCsr(int tag)
    {
        return tag switch
        {
            GeneralName.DnsName => "DNS",
            GeneralName.IPAddress => "IP",
            GeneralName.Rfc822Name => "Email",
            _ => "Other"
        };
      
    }

    public static CreateCsrRequest CreateCsrRequestFromCsrPem(
    string pem,
    Guid certificateProfileId,
    Guid signingProfileId)
    {
        var parsed = ParseCsr(pem);

        return new CreateCsrRequest
        {
            SubjectName = parsed.SubjectName,
            SubjectAlternativeNames = parsed.SubjectAlternativeNames,
            KeyAlgorithm = parsed.KeyAlgorithm,
            SignatureAlgorithm = parsed.SignatureAlgorithm,
            KeySize = parsed.KeySize,
            CertificateProfileId = certificateProfileId,
            SigningProfileId = signingProfileId
        };
    }

    public static byte[] ParseCrlFromPem(string pem)
    {
        using var sr = new StringReader(pem);
        var pemReader = new PemReader(sr);
        var crl = pemReader.ReadObject() as X509Crl
            ?? throw new InvalidOperationException("Invalid PEM CRL.");
        return crl.GetEncoded();
    }

    public static string ParseCnFromPem(string pem)
    {
        var certByte = ParseCertificate(ParseFromPem(pem));
        var cnPart = certByte.SubjectDN.Split(',')[0].Trim();
        return cnPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? cnPart.Substring(3).Trim() : cnPart;
    }

    public static string ParseCnFromDer(byte[] der)
    {
        var cert = new X509Certificate(der);
        var cnPart = cert.SubjectDN.ToString().Split(',')[0].Trim();
        return cnPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? cnPart.Substring(3).Trim() : cnPart;
    }
}
        
