using Org.BouncyCastle.X509;
using Org.BouncyCastle.OpenSsl;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.Secure;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.KeystoreFormat;
using System.Text;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.IO;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Models;
using ModularCA.Database;
using Org.BouncyCastle.Security;
using System.Runtime.ConstrainedExecution;
using Org.BouncyCastle.Crypto.Parameters;

namespace ModularCA.API.Startup
{
    public static class StartupKeystoreLoader
    {
        public static (List<CertKey> Signers, List<X509Certificate> TrustedCAs) LoadKeystorePairs(string yamlPath)
        {
            string certPath = Path.Combine(AppContext.BaseDirectory, "keystores", "ca-certs.keystore");
            string trustPath = Path.Combine(AppContext.BaseDirectory, "keystores", "ca-trust.keystore");

            var signerCerts = LoadCertKeys(certPath, yamlPath);
            var trustedCerts = LoadTrustedCerts(trustPath, yamlPath);

            return (signerCerts, trustedCerts);
        }

        private static List<CertKey> LoadCertKeys(string keystorePath, string yamlPath)
        {
            var keystore = KeystoreFileParser.Parse(keystorePath);
            var secondary = KeystoreYamlLoader.LoadSecondaryPassphrase(yamlPath, keystorePath);
            var main = LoadMainPassphrase(keystorePath);

            var key = ScryptKeyDeriver.DeriveFileKey(main, secondary, keystore);

            var result = new List<CertKey>();

            foreach (var entry in keystore.Entries)
            {
                var decrypted = AesGcmDecryptor.Decrypt(entry.Nonce, entry.Ciphertext, entry.Tag, key);
                var parsed = ParseDerKeys(decrypted);
                result.Add(parsed);
            }

            return result;
        }

        private static List<X509Certificate> LoadTrustedCerts(string keystorePath, string yamlPath)
        {
            var keystore = KeystoreFileParser.Parse(keystorePath);
            var secondary = KeystoreYamlLoader.LoadSecondaryPassphrase(yamlPath, keystorePath);
            var main = LoadMainPassphrase(keystorePath);

            var key = ScryptKeyDeriver.DeriveFileKey(main, secondary, keystore);
            var result = new List<X509Certificate>();

            foreach (var entry in keystore.Entries)
            {
                var decrypted = AesGcmDecryptor.Decrypt(entry.Nonce, entry.Ciphertext, entry.Tag, key);
                var certs = ParseDerCerts(decrypted);
                result.Add(certs);
            }

            return result;
        }

        public static CertKey ParseDerKeys(byte[] decrypted)
        {
            var privateKey = PrivateKeyFactory.CreateKey(decrypted);
            using var sw = new StringWriter();
            var pemWriter = new PemWriter(sw);
            pemWriter.WriteObject(privateKey);
            pemWriter.Writer.Flush();
            Console.WriteLine(sw.ToString());

            return new CertKey(privateKey);
        }

        public static X509Certificate ParseDerCerts(byte[] decrypted)
        {
            var publicKey = new X509Certificate(decrypted);
            Console.WriteLine(publicKey.GetPublicKey().ToString());

            return publicKey;
        }

        private static List<X509Certificate> ParseCertsFromPem(byte[] pemBytes)
        {
            var result = new List<X509Certificate>();
            using var reader = new StringReader(Encoding.UTF8.GetString(pemBytes));
            var pemReader = new PemReader(reader);
            object? item;
            while ((item = pemReader.ReadObject()) != null)
            {
                if (item is X509Certificate cert)
                    result.Add(cert);
            }
            return result;
        }

        private static List<CertWithKey> MatchCertsWithKeys(List<CertKey> privateKeys, List<X509Certificate> publicCerts)
        {
            var matches = new List<CertWithKey>();

            foreach (var cert in publicCerts)
            {
                var certPublicKey = cert.GetPublicKey();

                foreach (var key in privateKeys)
                {
                    try
                    {
                        var derivedPublic = GetPublicFromPrivate(key.PrivateKey);

                        if (certPublicKey.Equals(derivedPublic))
                        {
                            matches.Add(new CertWithKey(cert, key.PrivateKey));
                            break; // stop after first match
                        }
                    }
                    catch
                    {
                        // Ignore mismatches or unsupported keys
                    }
                }
            }

            return matches;
        }

        private static AsymmetricKeyParameter GetPublicFromPrivate(AsymmetricKeyParameter privateKey)
        {
            if (!privateKey.IsPrivate)
                throw new ArgumentException("Key is not a private key");

            return privateKey switch
            {
                RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
                ECPrivateKeyParameters ec => new ECPublicKeyParameters(
                    ec.AlgorithmName,
                    ec.Parameters.G.Multiply(ec.D),
                    ec.Parameters
                ),
                _ => throw new NotSupportedException("Unsupported key type")
            };
        }

        private static string LoadMainPassphrase(string keystorePath)
        {
            var name = Path.GetFileName(keystorePath); // e.g. "ca-certs.keystore"
            return KeystoreDbPassphraseLoader.RetrieveFromDatabase(name);
        }
        public static (List<CertKey> Signers, List<CertWithKey> FullCAs, List<X509Certificate> TrustedCAs) LoadAll(string keystorePath, string yamlPath)
        {

            var certPath = Path.Combine(keystorePath, "ca-certs.keystore");
            var trustPath = Path.Combine(keystorePath, "ca-trust.keystore");
            var privKeys = LoadCertKeys(certPath, yamlPath);
            var trustCAs = LoadTrustedCerts(trustPath, yamlPath);
            var fullCAs = MatchCertsWithKeys(privKeys, trustCAs);

            return (privKeys, fullCAs, trustCAs);
        }

        public record CertWithKey(
        X509Certificate Cert,
        AsymmetricKeyParameter PrivateKey
    );

        public record CertKey(
        AsymmetricKeyParameter PrivateKey
    );
        
    }
}