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

public class BouncyCastleCertificateAuthority(byte[] caCertBytes, byte[] caKeyBytes) : ICertificateAuthority
{
    private readonly X509Certificate _issuerCert = LoadCertificate(caCertBytes);
    private readonly AsymmetricKeyParameter _issuerKey = LoadPrivateKey(caKeyBytes);

    public async Task<byte[]> IssueCertificateAsync(CertificateRequestModel request)
    {
        var subjectKeyPair = GenerateKeyPair(request.KeyAlgorithm, request.KeySize);

        var serial = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), new SecureRandom());
        var notBefore = request.NotBefore;
        var notAfter = request.NotAfter;

        var subjectDN = new X509Name(BuildSubject(request));
        var issuerDN = _issuerCert.SubjectDN;

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serial);
        certGen.SetIssuerDN(issuerDN);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetPublicKey(subjectKeyPair.Public);

        // Basic Constraints (CA flag)
        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(request.IsCA));

        // Key Usage
        if (request.KeyUsages.Any())
        {
            var flags = request.KeyUsages
                .Select(ParseKeyUsage)
                .Aggregate((a, b) => a | b);
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(flags));
        }

        // Extended Key Usage
        if (request.ExtendedKeyUsages.Any())
        {
            var usages = request.ExtendedKeyUsages.Select(u => new DerObjectIdentifier(u)).ToList();
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(usages));
        }

        // Subject Alternative Name
        if (request.SubjectAlternativeNames.Any())
        {
            var altNames = request.SubjectAlternativeNames
                .Select(name => name.Contains(":") ? name : $"DNS:{name}")
                .Select(GeneralNameFactory)
                .ToArray();

            var subjectAltNames = new DerSequence(altNames);
            certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltNames);
        }

        // Sign certificate
        var signer = new Asn1SignatureFactory(GetSignatureAlgorithm(request.KeyAlgorithm), _issuerKey, new SecureRandom());
        var cert = certGen.Generate(signer);

        return cert.GetEncoded(); // DER-encoded X.509 cert
    }

    public async Task<byte[]> IssueSelfSignedCACertificateAsync(CertificateRequestModel request)
    {
        var subjectKeyPair = GenerateKeyPair(request.KeyAlgorithm, request.KeySize);

        var serial = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), new SecureRandom());
        var notBefore = request.NotBefore;
        var notAfter = request.NotAfter;

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
        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(request.IsCA));

        // Key Usage
        if (request.KeyUsages.Any())
        {
            var flags = request.KeyUsages
                .Select(ParseKeyUsage)
                .Aggregate((a, b) => a | b);
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(flags));
        }

        // Extended Key Usage
        if (request.ExtendedKeyUsages.Any())
        {
            var usages = request.ExtendedKeyUsages.Select(u => new DerObjectIdentifier(u)).ToList();
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(usages));
        }

        // Subject Alternative Name
        if (request.SubjectAlternativeNames.Any())
        {
            var altNames = request.SubjectAlternativeNames
                .Select(name => name.Contains(":") ? name : $"DNS:{name}")
                .Select(GeneralNameFactory)
                .ToArray();

            var subjectAltNames = new DerSequence(altNames);
            certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltNames);
        }

        // Sign certificate
        var signer = new Asn1SignatureFactory(GetSignatureAlgorithm(request.KeyAlgorithm), _issuerKey, new SecureRandom());
        var cert = certGen.Generate(signer);

        return cert.GetEncoded(); // DER-encoded X.509 cert
    }

    public Task<bool> RevokeCertificateAsync(string serialNumber, string reason) =>
        Task.FromResult(false); // Not implemented yet

    public Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber) =>
        Task.FromResult<CertificateInfoModel?>(null); // Not implemented yet

    // ========== Helpers ==========

    private static X509Certificate LoadCertificate(byte[] derBytes)
    {
        var parser = new X509CertificateParser();
        return parser.ReadCertificate(derBytes);
    }


    private static AsymmetricKeyParameter LoadPrivateKey(byte[] derBytes)
    {
        return PrivateKeyFactory.CreateKey(derBytes);
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

    private static int ParseKeyUsage(string name) =>
        name.ToLowerInvariant() switch
        {
            "digitalsignature" => KeyUsage.DigitalSignature,
            "keyencipherment" => KeyUsage.KeyEncipherment,
            "dataencipherment" => KeyUsage.DataEncipherment,
            "keycertsign" => KeyUsage.KeyCertSign,
            "crlsign" => KeyUsage.CrlSign,
            _ => 0
        };

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
    public async Task<byte[]> IssueCertificateFromCsrAsync(byte[] csrBytes, DateTime notBefore, DateTime notAfter, bool isCA = false)
    {
        var csr = new Pkcs10CertificationRequest(csrBytes);

        if (!csr.Verify())
            throw new InvalidOperationException("CSR signature is invalid.");

        var publicKey = csr.GetPublicKey();
        var subject = csr.GetCertificationRequestInfo().Subject;

        var certGen = new X509V3CertificateGenerator();

        certGen.SetSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), new SecureRandom()));
        certGen.SetIssuerDN(_issuerCert.SubjectDN);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetSubjectDN(subject);
        certGen.SetPublicKey(publicKey);

        // Optional: preserve extensions if CSR has them
        var attrs = csr.GetCertificationRequestInfo().Attributes;
        foreach (Asn1Encodable encodable in attrs)
        {
            var attr = AttributePkcs.GetInstance(encodable);

            if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
            {
                var extensions = X509Extensions.GetInstance(attr.AttrValues[0]);

                foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
                {
                    var ext = extensions.GetExtension(oid);
                    certGen.AddExtension(oid, ext.IsCritical, ext.Value);

                }
            }
        }
        // Required: Basic constraints
        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCA));

        // Sign it
        var signer = new Asn1SignatureFactory("SHA256WITHRSA", _issuerKey, new SecureRandom());
        var cert = certGen.Generate(signer);

        return cert.GetEncoded();
    }

}
