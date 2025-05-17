using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using ModularCA.Shared.Entities;
using ModularCA.Core.Interfaces;
using ModularCA.Database;
using Org.BouncyCastle.Utilities;
using ModularCA.Core.Models;
using ModularCA.Core.Services;
using Org.BouncyCastle.Asn1;
using ModularCA.Core.Utils;
using System.Text.Json;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using ModularCA.Core.Implementations;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Tls;

namespace ModularCA.Functions.Services
{
    public class CertificateIssuanceService : ICertificateIssuanceService
    {
        private readonly ModularCADbContext _db;
        private readonly IKeystoreCertificates _keystore;
        private readonly ICertificateStore _certStore;

        public CertificateIssuanceService(ModularCADbContext db, IKeystoreCertificates keystore, ICertificateStore certStore)
        {
            _db = db;
            _keystore = keystore;
            _certStore = certStore;
        }

        public async Task<string> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter, bool includeRoot)
        {
            var csrEntity = await _db.CertificateRequests
                .Include(c => c.SigningProfile)
                .Include(c => c.CertProfile)
                .FirstOrDefaultAsync(c => c.Id == csrId);
            if (ValidateCsrStatus(csrEntity) == false)
                throw new InvalidOperationException("CSR is not in a valid state for issuance");

            if (csrEntity == null)
                throw new InvalidOperationException("CSR not found");

            if (csrEntity.SigningProfile == null)
                throw new InvalidOperationException("No signing profile associated with CSR");

            if (string.IsNullOrWhiteSpace(csrEntity.CSR))
                throw new InvalidOperationException("CSR field is empty");

            var csrParser = new CsrParserService();
            var csr = csrParser.ParseFromPem(csrEntity.CSR);

            if (!csr.Verify())
                throw new InvalidOperationException("CSR signature verification failed");

            if (!(NotBeyondMaximumDate(notAfter, csrEntity.SigningProfile)))
                throw new Exception("NotAfter date is beyond the maximum allowed date");

            if (!(NotBeforeMinimumDate(notAfter, csrEntity.SigningProfile)))
                throw new Exception("notAfter date is before the minimum allowed date");

            if(!IsValidKeyParameters(csrEntity.KeyAlgorithm, csrEntity.KeySize, csrEntity.SignatureAlgorithm, csrEntity.SigningProfile))
                throw new Exception("Key algorithm and size are not compatible");

            var refCACert = _db.Certificates
                .FirstOrDefaultAsync(c => c.CertificateId == csrEntity.SigningProfile.IssuerId);
            var caMatch = _keystore.GetTrustedAuthorities().Find(ca =>
                ca.SubjectDN.ToString().Contains(refCACert.Result.SubjectDN, StringComparison.OrdinalIgnoreCase));

            if (caMatch == null)
                throw new InvalidOperationException($"No CA found with subject matching: {refCACert.Result.SubjectDN}");

            var caMatchPrivKey = _keystore.GetPrivateKeyFor(caMatch);

            var now = DateTime.UtcNow;
            var timeMax = DateTime.UtcNow + Iso8601ParserUtil.ParseIso8601(csrEntity.SigningProfile.ValidityPeriodMax);

            var validFrom = notBefore ?? now;
            var validTo = notAfter ?? timeMax;

            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), new SecureRandom());

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(caMatch.SubjectDN);
            certGen.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
            certGen.SetNotBefore(validFrom);
            certGen.SetNotAfter(validTo);
            certGen.SetPublicKey(csr.GetPublicKey());

            // === Extensions ===
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));


            var extendedOids = SetupAllowedExtendedOids(csrEntity.SigningProfile.ExtendedKeyUsages, _db);
            var standardOids = SetupAllowedStandardOids(csrEntity.SigningProfile.KeyUsages, _db);

            // KeyUsage

            if (standardOids.Count != 0)
            {
                int usageFlags = 0;

                foreach (var key in standardOids)
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

            // ExtendedKeyUsage
            if (extendedOids.Count != 0)
            {
                var usages = extendedOids.Select(u => new DerObjectIdentifier(u)).ToList();
                certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(usages));
            }

            // === Sign cert ===
            var signer = new Asn1SignatureFactory(caMatch.SignatureAlgorithm, caMatchPrivKey, new SecureRandom());
            var issuedCert = certGen.Generate(signer);

            var output = new StringBuilder();
            using (var writer = new StringWriter(output))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(issuedCert);
                if (includeRoot)
                    pemWriter.WriteObject(caMatch);
            }
            var thumbprints = GetCertThumbprints(issuedCert);


            var decryptedCsrPrivKey = DecryptPrivateKeyFromSerial(csrEntity.AesKeyEncryptionIv, csrEntity.EncryptedAesForPrivateKey, csrEntity.EncryptedPrivateKey, csrEntity.EncryptionCertSerialNumber, _db, _keystore);
            var (certIv, certEncryptedAes, certEncryptedPrivKey) = KeyEncryptionUtil.EncryptPrivateKey(caMatch.GetPublicKey(), decryptedCsrPrivKey);

            var certPem = output.ToString();
            var certBytes = issuedCert.GetEncoded();

            // === Save to DB ===
            var certModel = new CertificateInfoModel
            {
                Pem = certPem,
                SubjectDN = issuedCert.SubjectDN.ToString(),
                Issuer = issuedCert.IssuerDN.ToString(),
                SerialNumber = issuedCert.SerialNumber.ToString(16),
                NotBefore = issuedCert.NotBefore,
                NotAfter = issuedCert.NotAfter,
                ValidFrom = validFrom,
                ValidTo = validTo,
                IsCA = false,
                Revoked = false,
                Iv = certIv,
                EncryptedAesKey = certEncryptedAes,
                EncryptedPrivateKey = certEncryptedPrivKey,
                RevocationReason = null,
                Thumbprints = thumbprints, // TODO: Implement SHA1/SHA256 calculation
                CertProfileId = csrEntity.CertProfile.Id,
                SigningProfileId = csrEntity.SigningProfile.Id,
                KeyUsages = standardOids ?? [],
                ExtendedKeyUsages = extendedOids ?? [],
                SubjectAlternativeNames = new List<string>() // TODO: Parse from CSR if needed
            };

            await _certStore.SaveCertificateAsync(certBytes, certModel);
            SetCsrStatus(_db, csrEntity, certModel.SerialNumber);
            return certPem;
        }

        private static string GetCertThumbprints(X509Certificate cert)
        {
            byte[] sha1hash = SHA1.HashData(cert.GetEncoded());
            string sha1thumbprint = BitConverter.ToString(sha1hash).Replace("-", "").ToUpperInvariant();
            Console.WriteLine("SHA 1 Thumbprint: " + sha1thumbprint);
            byte[] sha256hash = SHA256.HashData(cert.GetEncoded());
            string sha256thumbprint = BitConverter.ToString(sha256hash).Replace("-", "").ToUpperInvariant();
            Console.WriteLine("SHA 256 Thumbprint: " + sha256thumbprint);
            var thumbprintDict = new Dictionary<string, string>
        {
            { "SHA 1", sha1thumbprint },
            { "SHA 256", sha256thumbprint }
        };
            return JsonSerializer.Serialize(thumbprintDict);
        }

        private static List<string> SetupAllowedExtendedOids(string allowedExtendedOids, ModularCADbContext db)
        {
            var extendedOidsDeserialize = JsonSerializer.Deserialize<List<string>>(allowedExtendedOids);
            var allowedExtended = db.OIDOptions
                .Where(o => o.KeyUsage == "Extended" && extendedOidsDeserialize.Contains(o.OID))
                .Select(o => o.OID)
                .ToList();
            return allowedExtended;
        }

        private static List<string> SetupAllowedStandardOids(string allowedStandardOids, ModularCADbContext db)
        {
            var standardOidsDeserialize = JsonSerializer.Deserialize<List<string>>(allowedStandardOids);
            var allowedStandard = db.OIDOptions
                .Where(o => o.KeyUsage == "Standard" && standardOidsDeserialize.Contains(o.FriendlyName))
                .Select(o => o.FriendlyName)
                .ToList();
            return allowedStandard;
        }

        private static AsymmetricKeyParameter DecryptPrivateKeyFromSerial(
            byte[] iv,
            byte[] encryptedAesKey,
            byte[] encryptedPrivateKey,
            string EncryptionCertSerialNumber,
            ModularCADbContext db,
            IKeystoreCertificates keystore)
        {
            var encryptorPrivKeySerial = db.Certificates
                .FirstOrDefault(c => c.SerialNumber == EncryptionCertSerialNumber);
            var encryptorPubKey = new X509CertificateParser();
            var encryptorCert = encryptorPubKey.ReadCertificate(encryptorPrivKeySerial.RawCertificate);
            var encryptorPrivKey = keystore.GetPrivateKeyFor(encryptorCert);

            return KeyEncryptionUtil.DecryptPrivateKey(encryptedAesKey, iv, encryptedPrivateKey, encryptorPrivKey);
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

        private static void SetCsrStatus(ModularCADbContext db, CertRequestEntity csr, string certSN)
        {
            var cert = db.Certificates.Where(c => c.SerialNumber == certSN).FirstOrDefaultAsync().Result;
            csr.Status = "Issued";
            csr.IssuedCertificateId = cert.CertificateId;
            db.CertificateRequests.Update(csr);
            db.SaveChanges();
        }

        private static bool ValidateCsrStatus(CertRequestEntity csr)
        {
            if (csr.Status == "Pending" && csr.IssuedCertificateId == null)
                return true;
            else
                return false;
        }

        private static bool NotBeyondMaximumDate(DateTime? notAfter, SigningProfileEntity signingProfile)
        {
            var maxDate = DateTime.UtcNow.Add(Iso8601ParserUtil.ParseIso8601(signingProfile.ValidityPeriodMax)); // Example: 1 year from now
            return notAfter <= maxDate;
        }

        private static bool NotBeforeMinimumDate(DateTime? notBefore, SigningProfileEntity signingProfile)
        {
            var minDate = DateTime.UtcNow.Add(Iso8601ParserUtil.ParseIso8601(signingProfile.ValidityPeriodMin)); // Example: 1 year from now
            return notBefore >= minDate;
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
            if (!validKeyAlgorithms.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
                throw new Exception("Key algorithm \"" + algorithm + "\" not found in signing profile.");
            if (!validKeySizes.Contains(keySize))
                throw new Exception("Key size \"" + keySize + "\" not found in signing profile.");
            if (!validSignatureAlgorithms.Contains(signatureAlgorithm, StringComparer.OrdinalIgnoreCase))
                throw new Exception("Signature algorithm \"" + signatureAlgorithm + "\" not found in signing profile.");

            // Check compatibility: signature algorithm should contain the key algorithm (e.g., "SHA256withRSA" contains "RSA")
            if (!signatureAlgorithm.Contains(algorithm, StringComparison.OrdinalIgnoreCase))
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
}
