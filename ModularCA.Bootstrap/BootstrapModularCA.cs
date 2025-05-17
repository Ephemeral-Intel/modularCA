using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ModularCA.Bootstrap.Models;
using ModularCA.Bootstrap.Services;
using ModularCA.Bootstrap.Utils;
using System.Data;
using MySql.Data.MySqlClient;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Utilities;
using ModularCA.Bootstrap.Data;
using ModularCA.Shared.Entities;
using Org.BouncyCastle.Asn1.Cmp;
using ModularCA.Keystore.Crypto;
using System.Text;
using Org.BouncyCastle.OpenSsl;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using static ModularCA.Bootstrap.Services.KeystoreService;
using Org.BouncyCastle.Pkcs;
using ModularCA.Core.Implementations;
using Org.BouncyCastle.Math;
using ModularCA.Core.Models;
using System.Text.Json;
using static System.Runtime.InteropServices.JavaScript.JSType;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Cms;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using ModularCA.Keystore.KeystoreFormat;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using ZstdSharp.Unsafe;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Tls;
using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Serialization;

namespace ModularCA.Bootstrap;

public class BootstrapModularCA
{

    public static void Main()
    {
        var configDir = Path.Combine(AppContext.BaseDirectory, "config");
        var keystoreDir = Path.Combine(AppContext.BaseDirectory, "keystores");
        string certPath = Path.Combine(keystoreDir, "ca-certs.keystore");
        string trustPath = Path.Combine(keystoreDir, "ca-trust.keystore");
        var bootstrapPath = Path.Combine(configDir, "BootstrapConfig.yaml");
        var OIDPath = Path.Combine(configDir, "OIDSeed.yaml");
        var OIDConfig = YamlOIDLoader.Load(OIDPath);
        var bootstrapConfig = YamlBootstrapLoader.Load(bootstrapPath);
        var appConnStr = $"Server={bootstrapConfig.SqlApp.Host};Port={bootstrapConfig.SqlApp.Port};Database={bootstrapConfig.SqlApp.Database};Uid={bootstrapConfig.SqlApp.Username};Pwd={bootstrapConfig.SqlApp.Password};";

        var (dbContext, dbConnection) = CreateDatabaseConnection(appConnStr);
        CreateDatabase(dbContext);

        bool dbHasCa = CheckDatabase(dbConnection, bootstrapConfig);
        bool needsConfirm = File.Exists(certPath) || File.Exists(trustPath) || dbHasCa;
        ConfirmDelete(needsConfirm, certPath, trustPath, dbContext, dbConnection, bootstrapConfig);

        // === OID Loading Logic ===
        LoadOidsToDb(dbContext, OIDConfig);

        var allowedRootCaStandardOids = new[] {
            "Digital Signature",
            "Key Encipherment",
            "Key Certificate Signing",
            "CRL Signing"
            };

        var allowedRootCaExtendedOids = new[] {
            "Server Authentication",
            "Client Authentication",
            "Code Signing",
            "Email Protection",
            "Time Stamping",
            "OCSP Signer"
        };

        var RootCaStandardOidsJson = SetupAllowedStandardOidsJson(allowedRootCaStandardOids, dbContext);
        var RootCaExtendedOidsJson = SetupAllowedExtendedOidsJson(allowedRootCaExtendedOids, dbContext);

        var KeyAlgorithms = new List<string> { "RSA", "ECDSA" };
        var KeySizes = new List<string> { "2048", "3072", "4096", "P-256", "P-384", "P-521" };
        var SignatureAlgorithms = new List<string> { "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA" };

        var KeyAlgorithmsJson = JsonSerializer.Serialize(KeyAlgorithms);
        var KeySizesJson = JsonSerializer.Serialize(KeySizes);
        var SignatureAlgorithmsJson = JsonSerializer.Serialize(SignatureAlgorithms);

        CreateCertProfile(dbContext, "Main CA Certificate Profile", "Default cert profile for self-signed CA certificates", allowedRootCaStandardOids, allowedRootCaExtendedOids, false, true);
        var caCertProfile = GetCertProfileFromDb(dbContext, "Main CA Certificate Profile");
        CreateSigningProfile(dbContext, "Main CA Signing Profile", "Default profile used for self-signing CA certificates", allowedRootCaStandardOids, allowedRootCaExtendedOids, null, caCertProfile,
            "P5Y", "P25Y", KeyAlgorithmsJson, KeySizesJson, SignatureAlgorithmsJson);
        var caSigningProfile = GetSigningProfileFromDb(dbContext, "Main CA Signing Profile");
        var caCertRequest = CreateCertificateRequest(bootstrapConfig.CA.Subject.CN, bootstrapConfig.CA.Subject.O, bootstrapConfig.CA.Subject.OU?.FirstOrDefault(),
            bootstrapConfig.CA.Subject.L, bootstrapConfig.CA.Subject.ST, bootstrapConfig.CA.Subject.C, bootstrapConfig.CA.Algorithm, bootstrapConfig.CA.KeySize,
            DateTime.UtcNow, DateTime.UtcNow.AddYears(bootstrapConfig.CA.ValidityYears), caSigningProfile.Id, allowedRootCaStandardOids, allowedRootCaExtendedOids, dbContext);

        var (signedCaCert, caPrivKey, caPrivateKeyDer) = CreateSelfSignedCertificate(caCertRequest);

        var sysCertRequest = CreateCertificateRequest("System Signing CA Certificate", "Local System", null,
            bootstrapConfig.CA.Subject.L, bootstrapConfig.CA.Subject.ST, bootstrapConfig.CA.Subject.C,
            bootstrapConfig.CA.Algorithm, bootstrapConfig.CA.KeySize,
            DateTime.UtcNow, DateTime.UtcNow.AddYears(100), caSigningProfile.Id, allowedRootCaStandardOids, allowedRootCaExtendedOids, dbContext);
        var (signedSysCert, sysPrivKey, sysPrivateKeyDer) = CreateSelfSignedCertificate(sysCertRequest);

        var caCertPem = KeystoreService.ExportCertificateToPem(signedCaCert);
        var caKeyPem = KeystoreService.ExportPrivateKeyToPem(caPrivKey);

        Console.WriteLine("\n🎉 CA Certificate Bootstrap complete:");
        Console.WriteLine($" - CA cert PEM:\n{caCertPem}");
        Console.WriteLine($" - CA key PEM:\n{caKeyPem}");

        var sysCertPem = KeystoreService.ExportCertificateToPem(signedCaCert);
        var sysKeyPem = KeystoreService.ExportPrivateKeyToPem(caPrivKey);

        Console.WriteLine("\n🎉 CA Certificate Bootstrap complete:");
        Console.WriteLine($" - System CA cert PEM:\n{sysCertPem}");
        Console.WriteLine($" - System CA key PEM:\n{sysKeyPem}");

        if (Directory.Exists(keystoreDir))
        {
            Console.WriteLine($"(i) Keystore directory already exists: {keystoreDir}");
        }
        else
        {
            Console.WriteLine($"(i) Creating keystore directory: {keystoreDir}");
            Directory.CreateDirectory(keystoreDir);
            Console.WriteLine($"✓ Keystore directory created: {keystoreDir}");
        }

        // === Modern Keystore Logic ===
        var keystorePasswords = new Dictionary<string, string>
        {
            { "ca-certs.keystore", GenerateRandomPassphrase.Generate() },
            { "ca-trust.keystore", GenerateRandomPassphrase.Generate() }
        };
        foreach (var kvp in keystorePasswords)
        {
            Console.WriteLine($"🔐 {kvp.Key} passphrase: {kvp.Value}");
        }

        var keystoreFilePasswords = new Dictionary<string, string>
        {
            { "ca-certs.keystore", GenerateRandomPassphrase.Generate() },
            { "ca-trust.keystore", GenerateRandomPassphrase.Generate() }
        };

        var secondaryPasses = new Dictionary<string, string>
        {
            { "ca-certs.keystore", keystoreFilePasswords["ca-certs.keystore"] },
            { "ca-trust.keystore", keystoreFilePasswords["ca-trust.keystore"] }
        };

        
        // Export cert/key to PEM bytes

        Console.WriteLine("\n🎉 Keystore Bootstrap complete:");
        Console.WriteLine(" - CA cert keystore written to: " + certPath);
        Console.WriteLine(" - CA trust keystore written to: " + trustPath);



        var keystoreEntries = new List<AddKeystoreEntry>
        {
            new AddKeystoreEntry("ca-trust.keystore", signedCaCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
            new AddKeystoreEntry("ca-trust.keystore", signedSysCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
            new AddKeystoreEntry("ca-certs.keystore", caPrivateKeyDer, secondaryPasses["ca-certs.keystore"]),
            new AddKeystoreEntry("ca-certs.keystore", sysPrivateKeyDer, secondaryPasses["ca-certs.keystore"])
        };

        var defaultFlags = new List<FeatureFlagEntity>
        {
            new FeatureFlagEntity { Name = "CRL.Enabled", Enabled = true },
            new FeatureFlagEntity { Name = "OCSP.Enabled", Enabled = true },
            new FeatureFlagEntity { Name = "Audit.Enabled", Enabled = false },
        };

        WriteCertsToKeystore(keystorePasswords, keystoreEntries, caPrivKey, sysPrivKey, dbContext);

        var rootCaEntry = CreateCertificateEntry(dbContext, caCertPem, signedCaCert, caPrivateKeyDer, RootCaStandardOidsJson, RootCaExtendedOidsJson, caCertProfile, caSigningProfile);
        CreateCertificateEntry(dbContext, sysCertPem, signedSysCert, sysPrivateKeyDer, RootCaStandardOidsJson, RootCaExtendedOidsJson, caCertProfile, caSigningProfile);

        var allowedCertStandardOids = new[] {
            "Digital Signature",
            "Key Encipherment",
            };

        var allowedCertExtendedOids = new[] {
            "Server Authentication",
            "Client Authentication",
            "Email Protection",
        };

        CreateCertProfile(dbContext, "Main Certificate Profile", "Default cert profile for non-CA certificates", allowedCertStandardOids, allowedCertExtendedOids, false, false);
        var nonCaCertProfile = GetCertProfileFromDb(dbContext, "Main Certificate Profile");
        CreateSigningProfile(dbContext, "Main Certificate Signing Profile", "Default profile used for non-CA certificates", allowedCertStandardOids, allowedCertExtendedOids, rootCaEntry, nonCaCertProfile,
            "P47D", "P1Y", KeyAlgorithmsJson, KeySizesJson, SignatureAlgorithmsJson);

        AddFeatureFlagsToDb(dbContext, defaultFlags);

        CreateCrlSchedule(dbContext);

        WriteKeystorePasswordsToFile(configDir, keystorePasswords, keystoreFilePasswords);

        if (dbConnection.State == ConnectionState.Open) {
            dbConnection.Close();
        }

        WriteDatabaseEntriesToFile(configDir, bootstrapConfig);
    }

    public static (BootstrapDbContext, MySqlConnection dbConnect) CreateDatabaseConnection(string appConnStr)
    {
        var dbContext = new BootstrapDbContext(appConnStr);
        var conn = new MySqlConnection(appConnStr);
        CreateDatabase(dbContext);
        conn.Open();
        return (dbContext, conn);
    }

    public static void CreateDatabase(BootstrapDbContext dbConnection)
    {
        dbConnection.Database.EnsureCreated();
    }

    public static bool CheckDatabase(MySqlConnection conn, YamlBootstrapLoader.BootstrapConfig bootstrapConfig)
    {
        bool dbhasCa = false;

        try
        {

            using var cmd = new MySqlCommand(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = @db AND table_name = 'Certificates'", conn);
            cmd.Parameters.AddWithValue("@db", bootstrapConfig.SqlApp.Database);

            var exists = Convert.ToInt32(cmd.ExecuteScalar()) > 0;
            if (exists)
            {
                using var checkCmd = new MySqlCommand("SELECT COUNT(*) FROM Certificates WHERE IsCa = 1", conn);
                dbhasCa = Convert.ToInt32(checkCmd.ExecuteScalar()) > 0;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(i) Skipping CA check — reason: {ex.Message}");
        }
        return dbhasCa;
    }

    public static void ConfirmDelete(bool needsConfirm, string certPath, string trustPath, BootstrapDbContext db, MySqlConnection conn, YamlBootstrapLoader.BootstrapConfig bootstrapConfig)
    {
        if (needsConfirm)
        {
            Console.WriteLine("⚠️  Existing CA artifacts detected.");
            for (int i = 1; i <= 3; i++)
            {
                string prompt = i switch
                {
                    1 => "[DESTROY]",
                    2 => "[REALLY]",
                    3 =>    "[YES]",
                    _ => "[CONFIRM]"
                };
                Console.Write($"[{i}/3] Confirm destruction {prompt}: ");
                if (Console.ReadLine()?.Trim().ToUpperInvariant() != prompt.Trim('[', ']'))
                {
                    Console.WriteLine("❌ Confirmation failed. Aborting bootstrap.");
                    Environment.Exit(1);
                }
            
            }
            Console.WriteLine("✅ Destruction confirmed. Proceeding...\n");
            DeleteArtifacts(certPath, trustPath);
            ReconstructDatabase(db, conn, bootstrapConfig);
            
        }
    }

    public static void DeleteArtifacts(string certPath, string trustPath)
    {
        if (File.Exists(certPath))
            File.Delete(certPath);
        else
        {
            Console.WriteLine($"(i) {certPath} not found. Skipping deletion.");
        }

        if (File.Exists(trustPath))
            File.Delete(trustPath);
        else
        {
            Console.WriteLine($"(i) {trustPath} not found. Skipping deletion.");
        }
    }

    public static void ReconstructDatabase(BootstrapDbContext db, MySqlConnection conn, YamlBootstrapLoader.BootstrapConfig bootstrapConfig)
    {
        try
        {
            using var dropCmd = new MySqlCommand($"DROP DATABASE IF EXISTS `{bootstrapConfig.SqlApp.Database}`", conn);
            dropCmd.ExecuteNonQuery();
            using var createCmd = new MySqlCommand($"CREATE DATABASE `{bootstrapConfig.SqlApp.Database}`", conn);
            createCmd.ExecuteNonQuery();
            db.Database.EnsureCreated();
            Console.WriteLine($"✓ Database '{bootstrapConfig.SqlApp.Database}' dropped and recreated.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(!!) Failed to reset database: {ex.Message}");
        }
    }
    public static void LoadOidsToDb(BootstrapDbContext db, YamlOIDLoader.OIDSeedConfig OIDConfig)
    {
        if (db.OIDOptions.Any())
        {
            Console.WriteLine("✓ OIDs already loaded into the database.");
            return;
        }

        var standardOids = OIDConfig.OID.StandardKeyUsage;

        for (var oid = 0; oid < standardOids.Count; oid++)
        {
            db.OIDOptions.Add(new OIDOptionEntity
            {
                OID = standardOids.Values.ToList()[oid],
                FriendlyName = standardOids.Keys.ToList()[oid],
                IsDefaultEntry = true,
                KeyUsage = "Standard"
            });

            db.SaveChanges();
        }

        var extendedOids = OIDConfig.OID.ExtendedKeyUsage;

        for (var oid = 0; oid < extendedOids.Count; oid++)
        {
            db.OIDOptions.Add(new OIDOptionEntity
            {
                OID = extendedOids.Values.ToList()[oid],
                FriendlyName = extendedOids.Keys.ToList()[oid],
                IsDefaultEntry = true,
                KeyUsage = "Extended"
            });

            db.SaveChanges();
        }

        Console.WriteLine("✓ OIDs loaded into the database.");
    }

    public static List<string> SetupAllowedStandardOids(string[] allowedStandardOids, BootstrapDbContext db)
    {
        var allowedStandard = db.OIDOptions
            .Where(o => o.KeyUsage == "Standard" && allowedStandardOids.Contains(o.FriendlyName))
            .Select(o => o.FriendlyName)
            .ToList();
        return allowedStandard;
    }

    public static string SetupAllowedStandardOidsJson(string[] allowedStandardOids, BootstrapDbContext db)
    {
        var allowedStandard = SetupAllowedStandardOids(allowedStandardOids, db);
        var allowedStandardJson = JsonSerializer.Serialize(allowedStandard);
        return allowedStandardJson;
    }

    public static List<string> SetupAllowedExtendedOids(string[] allowedExtendedOids, BootstrapDbContext db)
    {
        var allowedExtended = db.OIDOptions
            .Where(o => o.KeyUsage == "Extended" && allowedExtendedOids.Contains(o.FriendlyName))
            .Select(o => o.OID)
            .ToList();
        return allowedExtended;
    }

    public static string SetupAllowedExtendedOidsJson(string[] allowedExtendedOids, BootstrapDbContext db)
    {
        var allowedExtended = SetupAllowedExtendedOids(allowedExtendedOids, db);
        var allowedExtendedJson = JsonSerializer.Serialize(allowedExtended);
        return allowedExtendedJson;
    }

    public static void CreateCertProfile(BootstrapDbContext db, string certProfileName, string certProfileDescription, string[] keyUsage, string[] extendedKeyUsage, bool canBeDeleted, bool isCaProfile)
    {

        if (db.CertProfiles.Any(c => c.Name == certProfileName))
        {
            throw new InvalidOperationException($"A certificate profile with the name '{certProfileName}' already exists.");
        }
        var StandardKeyOidsJson = SetupAllowedStandardOidsJson(keyUsage, db);
        var ExtendedKeyOidsJson = SetupAllowedExtendedOidsJson(extendedKeyUsage, db);
        var certProfile = new CertProfileEntity
        {
            Id = Guid.NewGuid(),
            Name = certProfileName,
            IsCaProfile = isCaProfile,
            Description = certProfileDescription,
            IncludeRootInChain = true,
            KeyUsage = StandardKeyOidsJson,
            ExtendedKeyUsage = ExtendedKeyOidsJson,
            ValidityPeriod = "P2Y", // ISO-8601 for 2 years
            CreatedAt = DateTime.UtcNow,
            CanBeDeleted = canBeDeleted
        };
        db.CertProfiles.Add(certProfile);
        db.SaveChanges();
        Console.WriteLine($"✓ Certificate profile '{certProfile.Name}' inserted into database.");
    }

    public static CertProfileEntity GetCertProfileFromDb(BootstrapDbContext db, string certProfileName)
    {
        var certProfile = db.CertProfiles
            .Where(p => p.Name == certProfileName)
            .FirstOrDefaultAsync();
        if (certProfile.Result == null)
            throw new Exception("Default cert profile not found.");
        return certProfile.Result;
    }

    public static void CreateSigningProfile(BootstrapDbContext db, string signingProfileName, string signingProfileDescription, string[] keyUsages,
        string[] extendedKeyUsages, CertificateEntity? issuer, CertProfileEntity certProfile, string validityPeriodMin, string validityPeriodMax,
        string keyAlgorithm, string keySize, string signatureAlgorithm)
    {
        // Check if a signing profile with the same name already exists
        if (db.SigningProfiles.Any(sp => sp.Name == signingProfileName))
        {
            throw new InvalidOperationException($"A signing profile with the name '{signingProfileName}' already exists.");
        }

        var standardKeyOidsJson = SetupAllowedStandardOidsJson(keyUsages, db);
        var extendedKeyOidsJson = SetupAllowedExtendedOidsJson(extendedKeyUsages, db);

        var signingProfile = new SigningProfileEntity
        {
            Name = signingProfileName,
            Description = signingProfileDescription,
            KeyUsages = standardKeyOidsJson,
            ExtendedKeyUsages = extendedKeyOidsJson,
            ValidityPeriodMin = validityPeriodMin,
            ValidityPeriodMax = validityPeriodMax,
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize,
            SignatureAlgorithm = signatureAlgorithm,
            Issuer = issuer,
            IssuerId = issuer?.CertificateId,
            CertProfile = certProfile,
            CertProfileId = certProfile.Id
        };

        db.SigningProfiles.Add(signingProfile);
        db.SaveChanges();
        Console.WriteLine($"✓ Signing profile '{signingProfile.Name}' inserted into database.");
    }

    public static SigningProfileEntity GetSigningProfileFromDb(BootstrapDbContext db, string signingProfileName)
    {
        var signingProfile = db.SigningProfiles
            .Where(p => p.Name == signingProfileName)
            .FirstOrDefaultAsync();
        if (signingProfile.Result == null)
            throw new Exception("Default signing profile not found.");
        return signingProfile.Result;
    }

    public static CertificateRequestModel CreateCertificateRequest(string commonName, string organization, string organizationalUnit,
        string locality, string state, string country, string keyAlgorithm, int keySize, DateTime notBefore,
        DateTime notAfter, Guid signingProfileId, string[] standardKeyUsage, string[] extendedKeyUsage, BootstrapDbContext db)
    {
        var standardKeyUsages = SetupAllowedStandardOids(standardKeyUsage, db);
        var extendedKeyUsages = SetupAllowedExtendedOids(extendedKeyUsage, db);

        var certRequestModel = new CertificateRequestModel
        {
            CommonName = commonName,
            Organization = organization,
            OrganizationalUnit = organizationalUnit,
            Locality = locality,
            State = state,
            Country = country,
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize,
            NotBefore = notBefore,
            NotAfter = notAfter,
            SigningProfileId = signingProfileId,
            IsCA = true,
            KeyUsages = standardKeyUsages,
            ExtendedKeyUsages = extendedKeyUsages
        };

        Console.WriteLine($"✓ Certificate request '{certRequestModel.CommonName}' created and ready for self-signing.");
        return certRequestModel;
    }

    public static (Org.BouncyCastle.X509.X509Certificate caCert, AsymmetricKeyParameter privKey, byte[] privKeyDer) CreateSelfSignedCertificate(CertificateRequestModel certRequest)
    {
        var CaCert = new SelfSignBouncyCastleCertificateAuthority();
        var finalCertBytes = CaCert.IssueSelfSignedCACertificate(certRequest);
        var caCert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(finalCertBytes.Certificate);
        var privKey = finalCertBytes.PrivateKey;
        var privateKeyDer = PrivateKeyInfoFactory
            .CreatePrivateKeyInfo(privKey)
            .ToAsn1Object()
            .GetDerEncoded();
        Console.WriteLine($"✓ Self-signed certificate '{caCert.SubjectDN}' created.");
        return (caCert, privKey, privateKeyDer);
    }

    public static void WriteCertsToKeystore(Dictionary<string, string> keystorePasswords, List<AddKeystoreEntry> keystoreEntries, AsymmetricKeyParameter privKeySigner1, AsymmetricKeyParameter privKeySigner2, BootstrapDbContext db)
    {
        var keystoreGroups = keystoreEntries.GroupBy(e => e.Keystore);

        foreach (var group in keystoreGroups)
        {
            var keystoreName = group.Key;
            var keystorePath = Path.Combine(AppContext.BaseDirectory, "keystores", keystoreName);
            var mainPass = keystorePasswords[keystoreName];

            // Create a new service with dual signers
            var keystoreService = new KeystoreService(
                keystorePath,
                mainPass,
                privKeySigner1,      // signer1
                privKeySigner2    // signer2
            );

            foreach (var entry in group)
            {
                keystoreService.AddEntry(entry.Payload, entry.SecondaryPass);
                WriteKeystoreFile(keystoreService, keystoreName, mainPass, entry.SecondaryPass, db);
            }

        }
    }

    public static void WriteKeystoreFile(KeystoreService keystoreService, string keystoreName, string mainPass, string secondaryPass, BootstrapDbContext db)
    {
        var scryptParams = keystoreService.Save();
        var file = new KeystoreFile
        {
            ScryptSalt = Convert.ToBase64String(scryptParams.Salt),
            ScryptN = scryptParams.Params.N,
            ScryptR = scryptParams.Params.R,
            ScryptP = scryptParams.Params.P
        };
        var kek = ScryptKeyDeriver.DeriveFileKey("ModularCA:PassWrap", secondaryPass, file);
        var blob = AesGcmEncryptor.Encrypt(Encoding.UTF8.GetBytes(mainPass), kek);
        var theBlob = blob.nonce.Concat(blob.ciphertext).Concat(blob.tag).ToArray();
        AddKeystoreEntryToDb(keystoreName, theBlob, scryptParams, mainPass, db);
    }

    public static void AddKeystoreEntryToDb(string keystoreName, byte[] theBlob, KeystoreSaveResult scryptParams, string mainPass, BootstrapDbContext db)
    {
        var keystoreEntry = new KeystoreEntryEntity
        {
            Name = keystoreName,
            PassHash = CryptoUtils.HashPass(mainPass),
            Passblob = theBlob,
            Salt = Convert.ToBase64String(scryptParams.Salt),
            ScryptN = scryptParams.Params.N,
            ScryptR = scryptParams.Params.R,
            ScryptP = scryptParams.Params.P,
            CreatedAt = DateTime.UtcNow,
            Enabled = true
        };
        db.Keystores.Add(keystoreEntry);
        db.SaveChanges();
        Console.WriteLine($"✓ Keystore '{keystoreName}' entry added to database.");
    }

    public static string GetCertThumbprints(Org.BouncyCastle.X509.X509Certificate cert)
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

    public static CertificateEntity CreateCertificateEntry(BootstrapDbContext db, string certPem, Org.BouncyCastle.X509.X509Certificate caCert, byte[] privateKeyDer, string standardOidsJson, string extendedOidsJson, CertProfileEntity certProfile, SigningProfileEntity signingProfile)
    {

        var thumbprints = GetCertThumbprints(caCert);
        string publicKeyPem = certPem; // It's already in PEM format

        var encPubKey = (RsaKeyParameters)caCert.GetPublicKey();
        var aesKey = new byte[32];
        var iv = new byte[16];
        new SecureRandom().NextBytes(aesKey);
        new SecureRandom().NextBytes(iv);

        // Step 2: AES encryption of privateKeyDer
        var cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", aesKey), iv));
        var encryptedPrivateKey = cipher.DoFinal(privateKeyDer);

        // Step 3: Encrypt AES key with RSA OAEP
        var engine = new OaepEncoding(new RsaEngine());
        engine.Init(true, encPubKey);
        var encryptedAesKey = engine.ProcessBlock(aesKey, 0, aesKey.Length);

        var emptyJson = new List<string>();

        // Now save to DB
        var certEntity = new CertificateEntity
        {
            Pem = publicKeyPem,
            NotBefore = caCert.NotBefore,
            NotAfter = caCert.NotAfter,
            ValidFrom = caCert.NotBefore,
            ValidTo = caCert.NotAfter,
            Issuer = caCert.IssuerDN.ToString(),
            SubjectDN = caCert.SubjectDN.ToString(),
            SerialNumber = caCert.SerialNumber.ToString(),
            Thumbprints = thumbprints,
            KeyUsagesJson = standardOidsJson,
            EncryptedPrivateKey = encryptedPrivateKey,
            AesKeyEncryptionIv = iv,
            EncryptedAesForPrivateKey = encryptedAesKey,
            ExtendedKeyUsagesJson = extendedOidsJson,
            SubjectAlternativeNamesJson = JsonSerializer.Serialize(emptyJson),
            CertProfileId = certProfile.Id,
            CertProfile = certProfile,
            SigningProfileId = signingProfile.Id,
            SigningProfile = signingProfile,
            RawCertificate = caCert.GetEncoded(),

            IsCA = true
        };

        db.Certificates.Add(certEntity);
        db.SaveChanges();

        return certEntity;
    }


    public static void AddFeatureFlagsToDb(BootstrapDbContext db, List<FeatureFlagEntity> featureFlagEntry)
    {
        foreach (var flag in featureFlagEntry)
        {
            if (!db.FeatureFlags.Any(f => f.Name == flag.Name))
                db.FeatureFlags.Add(flag);
            db.SaveChanges();
            Console.WriteLine($"✓ Feature flag '{flag.Name}' added to database.");
        }
    }

    public static void CreateCrlSchedule(BootstrapDbContext db)
    {
        var crlSchedule = new CrlConfigurationEntity
        {
            Name = "Default CRL Schedule",
            Description = "Default schedule for CRL generation",
            Interval = TimeSpan.FromDays(7),
            OverlapPeriod = TimeSpan.FromHours(1),
            EnableDelta = false,
            LastGenerated = DateTime.UtcNow
        };
        db.CrlConfigurations.Add(crlSchedule);
        db.SaveChanges();
        Console.WriteLine($"✓ CRL schedule '{crlSchedule.Name}' added to database.");
    }


    public static void WriteKeystorePasswordsToFile(string configDir, Dictionary<string, string> keystorePasswords, Dictionary<string, string> secondaryPasses)
    {
        var yamlLines = keystorePasswords.Select(kvp =>
        {
            var secondary = secondaryPasses.TryGetValue(kvp.Key, out string? value) ? value : "";
            return $"{kvp.Key}: {secondary}";
        }).ToList();

        var yamlPath = Path.Combine(configDir, "keystore.yaml");
        File.WriteAllLines(yamlPath, yamlLines);

        Console.WriteLine($"\n📝 Secondary passphrases written to: {yamlPath}");
    }

    public static void WriteDatabaseEntriesToFile(string configDir, YamlBootstrapLoader.BootstrapConfig bootstrapConfig)
    {
        var dbConfig = new
        {
            App = bootstrapConfig.SqlApp,
            Audit = bootstrapConfig.SqlAudit
        };

        var serializer = new SerializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .Build();

        var yaml = serializer.Serialize(dbConfig);

        var yamlPath = Path.Combine(configDir, "db.yaml");
        File.WriteAllText(yamlPath, yaml);

        Console.WriteLine($"\n📝 Database configuration written to: {yamlPath}");
    }
}
