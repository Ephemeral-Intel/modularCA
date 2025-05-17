using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;

namespace ModularCA.Core.Implementations;

public class LocalCertificateAuthority : ICertificateAuthority
{
    private readonly X509Certificate2 _issuerCert;
    private readonly RSA _issuerKey;

    public LocalCertificateAuthority(string pfxPath, string password = "")
    {
        _issuerCert = new X509Certificate2(pfxPath, password, X509KeyStorageFlags.Exportable);
        _issuerKey = _issuerCert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("CA certificate does not contain an RSA private key.");
    }

    public async Task<byte[]> IssueCertificateAsync(CertificateRequestModel request)
    {
        using var subjectKey = RSA.Create(request.KeySize);
        var subject = BuildSubject(request);

        var certReq = new CertificateRequest(subject, subjectKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Basic constraints (CA or not)
        certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(request.IsCA, false, 0, true));

        // Key Usage
        if (request.KeyUsages.Any())
        {
            var usage = request.KeyUsages
                .Select(ParseKeyUsage)
                .Aggregate((a, b) => a | b);
            certReq.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        }

        // Extended Key Usage
        if (request.ExtendedKeyUsages.Any())
        {
            var eku = new OidCollection();
            foreach (var oid in request.ExtendedKeyUsages)
                eku.Add(new Oid(oid));
            certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));
        }

        // Subject Alternative Name
        if (request.SubjectAlternativeNames.Any())
        {
            var builder = new SubjectAlternativeNameBuilder();
            foreach (var name in request.SubjectAlternativeNames)
            {
                if (IPAddress.TryParse(name, out var ip))
                    builder.AddIpAddress(ip);
                else
                    builder.AddDnsName(name);
            }
            certReq.CertificateExtensions.Add(builder.Build());
        }

        // Authority Key Identifier (optional)
        var aki = new X509SubjectKeyIdentifierExtension(_issuerCert.PublicKey, false);
        certReq.CertificateExtensions.Add(aki);

        // Generate and sign
        var serial = GenerateSerial();
        var cert = certReq.Create(_issuerCert, request.NotBefore, request.NotAfter, serial);

        return cert.Export(X509ContentType.Cert);
    }

    public Task<bool> RevokeCertificateAsync(string serialNumber, string reason) =>
        Task.FromResult(false); // Stub

    public Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber) =>
        Task.FromResult<CertificateInfoModel?>(null); // Stub

    // ========== Helpers ==========

    private static X500DistinguishedName BuildSubject(CertificateRequestModel req)
    {
        var dn = new List<string>();
        if (!string.IsNullOrWhiteSpace(req.CommonName)) dn.Add($"CN={req.CommonName}");
        if (!string.IsNullOrWhiteSpace(req.Organization)) dn.Add($"O={req.Organization}");
        if (!string.IsNullOrWhiteSpace(req.OrganizationalUnit)) dn.Add($"OU={req.OrganizationalUnit}");
        if (!string.IsNullOrWhiteSpace(req.Locality)) dn.Add($"L={req.Locality}");
        if (!string.IsNullOrWhiteSpace(req.State)) dn.Add($"ST={req.State}");
        if (!string.IsNullOrWhiteSpace(req.Country)) dn.Add($"C={req.Country}");
        return new X500DistinguishedName(string.Join(", ", dn));
    }

    private static byte[] GenerateSerial()
    {
        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        return serial;
    }

    private static X509KeyUsageFlags ParseKeyUsage(string usage) =>
        usage.ToLowerInvariant() switch
        {
            "digitalsignature" => X509KeyUsageFlags.DigitalSignature,
            "keyencipherment" => X509KeyUsageFlags.KeyEncipherment,
            "dataencipherment" => X509KeyUsageFlags.DataEncipherment,
            "keycertsign" => X509KeyUsageFlags.KeyCertSign,
            "crlsign" => X509KeyUsageFlags.CrlSign,
            _ => 0
        };
    public Task<byte[]> IssueCertificateFromCsrAsync(byte[] csrBytes, DateTime notBefore, DateTime notAfter, bool isCA = false)
    {
        var pkcs10 = new Pkcs10CertificationRequest(csrBytes);

        if (!pkcs10.Verify())
            throw new InvalidOperationException("CSR signature is invalid.");

        var subject = new X500DistinguishedName(pkcs10.GetCertificationRequestInfo().Subject.GetEncoded());

        var pubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pkcs10.GetPublicKey());
        var pubKeyDer = pubKeyInfo.GetDerEncoded();
        var rsaPub = RSA.Create();
        rsaPub.ImportSubjectPublicKeyInfo(pubKeyDer, out _);

        var csr = new CertificateRequest(subject, rsaPub, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCA, false, 0, true));
        csr.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(_issuerCert.PublicKey, false));

        var serial = GenerateSerial();
        var cert = csr.Create(_issuerCert, notBefore, notAfter, serial);

        return Task.FromResult(cert.Export(X509ContentType.Cert));
    }


}
