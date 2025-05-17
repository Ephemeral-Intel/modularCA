using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using ModularCA.Core.Interfaces;
using ModularCA.Shared.Models.Csr;
using ModularCA.Core.Utils;
using Org.BouncyCastle.OpenSsl;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json;

namespace ModularCA.Functions.Services;

public class CsrService : ICsrService
{
    private readonly ModularCADbContext _dbContext;
    private readonly IKeystoreCertificates _keystore;

    public CsrService(ModularCADbContext dbContext, IKeystoreCertificates keystore)
    {
        _dbContext = dbContext;
        _keystore = keystore;
    }

    public async Task<string> GenerateCsrAsync(CreateCsrRequest request)
    {
        // Load cert and signing profiles
        var certProfile = await _dbContext.CertProfiles.FindAsync(request.CertificateProfileId);
        var signingProfile = await _dbContext.SigningProfiles.FindAsync(request.SigningProfileId);

        if (certProfile == null)
            throw new Exception("Certificate profile not found.");
        if (signingProfile == null)
            throw new Exception("Signing profile not found.");

        if (!IsValidKeyParameters(request.KeyAlgorithm, request.KeySize, request.SignatureAlgorithm, signingProfile))
            throw new Exception("Invalid key parameters.");
        // Generate keypair
        var keyPair = KeyGenerationUtil.GenerateKeyPair(request.KeyAlgorithm, request.KeySize);

        // Build subject
        var subject = new X509Name(request.SubjectName);

        // Prepare extension list
        var extGen = new X509ExtensionsGenerator();

        // Key Usage
        if (!string.IsNullOrWhiteSpace(certProfile.KeyUsage))
        {
            var usageFlags = X509KeyUsageUtil.ParseKeyUsages(certProfile.KeyUsage);
            extGen.AddExtension(X509Extensions.KeyUsage, true, new X509KeyUsage(usageFlags));
        }

        List<string> ekuOidsFromJson = JsonSerializer.Deserialize<List<string>>(certProfile.ExtendedKeyUsage)!;

        var ekuDbOids = _dbContext.OIDOptions
    .Where(o => ekuOidsFromJson.Contains(o.OID))
    .Select(o => o.OID)
    .Select(o =>
    
    new DerObjectIdentifier(o)
    )
    .ToArray();

        var ekuSeq = new DerSequence(ekuDbOids);
        extGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, ekuSeq);
        var extensions = extGen.Generate();

        // Wrap extensions in a CSR attribute
        var attr = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));
        var attributes = new DerSet(attr);

        // Create CSR
        var csr = new Pkcs10CertificationRequest(
            request.SignatureAlgorithm ?? "SHA256WITHRSA",
            subject,
            keyPair.Public,
            attributes,
            keyPair.Private
        );

        // PEM encode CSR
        string csrPem;
        using (var sw = new StringWriter())
        {
            var pemWriter = new PemWriter(sw);
            pemWriter.WriteObject(csr);
            csrPem = sw.ToString();
        }

        // Encrypt private key with system encryption cert
        var encryptionCert = _keystore.GetTrustedAuthorities()
            .FirstOrDefault(ca => ca.SubjectDN.ToString()
            .Contains("System", StringComparison.OrdinalIgnoreCase));

        if (encryptionCert == null)
            throw new Exception("System encryption certificate not found.");

        var encryptedPrivKey = KeyEncryptionUtil.EncryptPrivateKey(
            encryptionCert.GetPublicKey(), keyPair.Private
        );

        // Store CSR and references to cert/signing profiles
        var entity = new CertRequestEntity
        {
            Subject = request.SubjectName,
            CSR = csrPem,
            KeyAlgorithm = request.KeyAlgorithm,
            KeySize = request.KeySize,
            SignatureAlgorithm = request.SignatureAlgorithm,
            EncryptedPrivateKey = encryptedPrivKey.encryptedPrivateKey,
            EncryptedAesForPrivateKey = encryptedPrivKey.aesKeyEncrypted,
            AesKeyEncryptionIv = encryptedPrivKey.iv,
            EncryptionCertSerialNumber = encryptionCert.SerialNumber.ToString(),
            SubmittedAt = DateTime.UtcNow,
            CertProfileId = certProfile.Id,
            CertProfile = certProfile,
            SigningProfileId = signingProfile.Id,
            SigningProfile = signingProfile
        };

        _dbContext.CertificateRequests.Add(entity);
        await _dbContext.SaveChangesAsync();

        return csrPem;
    }

    private static bool IsValidKeyParameters(string algorithm, string keySize, string signatureAlgorithm, SigningProfileEntity signingProfile)
    {
        // Deserialize allowed values from signing profile
        var validKeyAlgorithms = JsonSerializer.Deserialize<List<string>>(signingProfile.KeyAlgorithm);
        var validKeySizes = JsonSerializer.Deserialize<List<string>>(signingProfile.KeySize);
        var validSignatureAlgorithms = JsonSerializer.Deserialize<List<string>>(signingProfile.SignatureAlgorithm);

        // Check presence
        if (validKeyAlgorithms == null || validKeySizes == null || validSignatureAlgorithms == null)
            return false;

        // Check if all parameters are present in the profile
        if(!validKeyAlgorithms.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
            throw new Exception("Key algorithm \"" + algorithm + "\" not found in signing profile.");
        if(!validKeySizes.Contains(keySize))
            throw new Exception("Key size \"" + keySize + "\" not found in signing profile.");
        if(!validSignatureAlgorithms.Contains(signatureAlgorithm, StringComparer.OrdinalIgnoreCase))
            throw new Exception("Signature algorithm \"" + signatureAlgorithm + "\" not found in signing profile.");

        // Check compatibility: signature algorithm should contain the key algorithm (e.g., "SHA256withRSA" contains "RSA")
        if(!signatureAlgorithm.Contains(algorithm, StringComparison.OrdinalIgnoreCase))
            throw new Exception("Signature algorithm \"" + signatureAlgorithm + "\" is not compatible with key algorithm \"" + algorithm + "\".");

        if (!IsKeyAlgorithmAndSizeCompatible(algorithm, keySize))
            throw new Exception("Key algorithm \"" + algorithm + "\" and size \"" + keySize + "\" are not compatible.");

        return true;
    }
    private static bool IsKeyAlgorithmAndSizeCompatible(string algorithm, object keySizeOrCurve)
    {
        // Accepts keySizeOrCurve as int (for RSA/DSA) or string (for ECDSA curves)
        switch (algorithm.ToUpperInvariant())
        {
            case "RSA":
                if (keySizeOrCurve is int rsaSize)
                    return rsaSize == 2048 || rsaSize == 3072 || rsaSize == 4096;
                return false;
/* Not to be supported yet
            case "DSA":
                if (keySizeOrCurve is int dsaSize)
                    return dsaSize == 1024 || dsaSize == 2048 || dsaSize == 3072;
                return false;
*/
            case "ECDSA":
                if (keySizeOrCurve is string curveName)
                {
                    // Accept common NIST curves
                    var validCurves = new[] { "P-256", "P-384", "P-521", "secp256r1", "secp384r1", "secp521r1" };
                    return validCurves.Contains(curveName, StringComparer.OrdinalIgnoreCase);
                }
                return false;
            default:
                return false;
        }
    }

    
}
