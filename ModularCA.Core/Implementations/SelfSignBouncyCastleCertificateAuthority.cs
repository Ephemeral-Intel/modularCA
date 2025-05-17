using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;

using System.Text;

namespace ModularCA.Core.Implementations;

public class SelfSignBouncyCastleCertificateAuthority : ISelfSignCertificateAuthority
{
    private readonly X509Certificate _issuerCert;
    private readonly AsymmetricKeyParameter _issuerKey;

    public SelfSignBouncyCastleCertificateAuthority()
    {
    }

    public CaKeyPair IssueSelfSignedCACertificate(CertificateRequestModel request)
    {
        var subjectKeyPair = GenerateKeyPair(request.KeyAlgorithm, request.KeySize);

        var serial = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), new SecureRandom());
        var notBefore = request.NotBefore;
        var notAfter = request.NotAfter;
        var privateKey = subjectKeyPair.Private;

        var subjectDN = new X509Name(BuildSubject(request));
        var issuerDN = subjectDN;

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serial);
        certGen.SetIssuerDN(issuerDN);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetPublicKey(subjectKeyPair.Public);

        // Basic Constraints (CA flag)
        //certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(request.IsCA));

        // Key Usage
        if (request.KeyUsages.Count != 0)
        {
            int usageFlags = 0;

            foreach (var key in request.KeyUsages)
            {
                try
                {
                    var usageInt = ParseKeyUsage(key);
                    if (usageInt == -1) continue; // Skip invalid key usages
                    usageFlags |= usageInt; // Combine via bitwise OR
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"Key Usage: {key} could not be added. Skipping.\n");
                }
            }

            if (usageFlags != 0)
            {
                var keyUsage = new KeyUsage(usageFlags);
                certGen.AddExtension(X509Extensions.KeyUsage, true, keyUsage);
            }
        }

        // Extended Key Usage
        if (request.ExtendedKeyUsages.Count != 0)
        {
            var usages = request.ExtendedKeyUsages.Select(u => new DerObjectIdentifier(u)).ToList();
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(usages));
        }

        // Subject Alternative Name
        if (request.SubjectAlternativeNames.Count != 0)
        {
            var altNames = request.SubjectAlternativeNames
                .Select(name => name.Contains(':') ? name : $"DNS:{name}")
                .Select(GeneralNameFactory)
                .ToArray();

            var subjectAltNames = new DerSequence(altNames);
            certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltNames);
        }

        // Sign certificate
        var signer = new Asn1SignatureFactory(GetSignatureAlgorithm(request.KeyAlgorithm), privateKey, new SecureRandom());
        var cert = certGen.Generate(signer);

        return new CaKeyPair(cert.GetEncoded(), privateKey);
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair(string algorithm, int keySize)
    {
        var generator = GeneratorUtilities.GetKeyPairGenerator(algorithm.ToUpperInvariant());
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        return generator.GenerateKeyPair();
    }

    private static string GetSignatureAlgorithm(string algorithm) =>
        algorithm.ToUpperInvariant() switch
        {
            "RSA" => "SHA256WITHRSA",
            "ECDSA" => "SHA256WITHECDSA",
            "DILITHIUM" => "DILITHIUM3",  // Use OID in real case if necessary
            "SPHINCSPLUS" => "SPHINCSPLUS-SHAKE256",
            _ => throw new NotSupportedException($"Unsupported algorithm: {algorithm}")
        };

    private static string BuildSubject(CertificateRequestModel req)
    {
        var sb = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(req.CommonName)) sb.Append($"CN={req.CommonName}, ");
        if (!string.IsNullOrWhiteSpace(req.Organization)) sb.Append($"O={req.Organization}, ");
        if (!string.IsNullOrWhiteSpace(req.OrganizationalUnit)) sb.Append($"OU={req.OrganizationalUnit}, ");
        if (!string.IsNullOrWhiteSpace(req.Locality)) sb.Append($"L={req.Locality}, ");
        if (!string.IsNullOrWhiteSpace(req.State)) sb.Append($"ST={req.State}, ");
        if (!string.IsNullOrWhiteSpace(req.Country)) sb.Append($"C={req.Country}, ");
        return sb.ToString().TrimEnd(',', ' ');
    }

    private static int ParseKeyUsage(string name)
    {
        try
        {
            return name.Trim().ToLowerInvariant() switch
            {
                "digital signature" => KeyUsage.DigitalSignature,
                "non repudiation" => KeyUsage.NonRepudiation,
                "key encipherment" => KeyUsage.KeyEncipherment,
                "data encipherment" => KeyUsage.DataEncipherment,
                "key agreement" => KeyUsage.KeyAgreement,
                "key certificate signing" => KeyUsage.KeyCertSign,
                "crl signing" => KeyUsage.CrlSign,
                "encipher only" => KeyUsage.EncipherOnly,
                "decipher only" => KeyUsage.DecipherOnly,
                _ => throw new ArgumentException($"Unknown key usage: {name}")
            };
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Key Usage: {name} could not be parsed\n{ex}");
        }
        return -1;
    }
    private static GeneralName GeneralNameFactory(string name)
    {
        var parts = name.Split(':', 2);
        return parts[0].ToLower() switch
        {
            "dns" => new GeneralName(GeneralName.DnsName, parts[1]),
            "ip" => new GeneralName(GeneralName.IPAddress, parts[1]),
            _ => new GeneralName(GeneralName.DnsName, parts[1])
        };
    }

    public record CaKeyPair(byte[] Certificate, AsymmetricKeyParameter PrivateKey);

}
