using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.KeystoreFormat;

namespace ModularCA.Bootstrap.Services;

public class KeystoreService(string keystorePath, string mainPassword, AsymmetricKeyParameter signer1, AsymmetricKeyParameter signer2)
{
    private readonly List<AddKeystoreEntry> _entries = new();
    private readonly string _keystorePath = keystorePath;
    private readonly string _mainPassword = mainPassword;

    private readonly AsymmetricKeyParameter _signer1 = signer1; // e.g., CA
    private readonly AsymmetricKeyParameter _signer2 = signer2; // e.g., system

    public void AddEntry(byte[] payload, string secondaryPassword)
    {
        _entries.Add(new AddKeystoreEntry(_keystorePath, payload, secondaryPassword));
    }

    public KeystoreSaveResult Save()
    {
        if (!_entries.Any())
            throw new InvalidOperationException("Keystore is empty. No entries to write.");

        var (_, _, _, scryptParams, salt) = KeystoreEncryptor.GenerateEncryptedKeystore(
    _entries[0].Payload,
    _mainPassword,
    _entries[0].SecondaryPass
);

        var scrypt = new KeystoreFileWriter.ScryptParams(scryptParams.N, scryptParams.R, scryptParams.P);
        var encryptedEntries = new List<KeystoreFileWriter.EncryptedEntry>();

        foreach (var entry in _entries)
        {
            var tempFile = new KeystoreFile
            {
                ScryptSalt = Convert.ToBase64String(salt),
                ScryptN = scrypt.N,
                ScryptR = scrypt.R,
                ScryptP = scrypt.P
            };

            var key = ScryptKeyDeriver.DeriveFileKey(_mainPassword, entry.SecondaryPass, tempFile);

            var (nonce, ciphertext, tag) = AesGcmEncryptor.Encrypt(entry.Payload, key);
            var sig1 = SignData(ciphertext, _signer1);
            var sig2 = SignData(ciphertext, _signer2);

            encryptedEntries.Add(new KeystoreFileWriter.EncryptedEntry(nonce, ciphertext, tag, sig1, sig2));
        }

        var fileBytesToSign = SerializeKeystoreData(salt, scrypt, encryptedEntries);
        var finalSig1 = SignData(fileBytesToSign, _signer1);
        var finalSig2 = SignData(fileBytesToSign, _signer2);

        KeystoreFileWriter.WriteEntireKeystore(_keystorePath, salt, scrypt, encryptedEntries, finalSig1, finalSig2);

        Console.WriteLine($"✅ Keystore written to {_keystorePath} with {_entries.Count} entries.");

        return new KeystoreSaveResult(salt, scrypt);
    }

    public void Reencrypt(string? newMainPassword = null, string? newSecondaryPass = null, AsymmetricKeyParameter? newSigner1 = null, AsymmetricKeyParameter? newSigner2 = null)
    {
        var mainPass = newMainPassword ?? _mainPassword;

        var (_, _, _, scryptParams, salt) = KeystoreEncryptor.GenerateEncryptedKeystore(
    _entries[0].Payload,
    _mainPassword,
    _entries[0].SecondaryPass
);

        var scrypt = new KeystoreFileWriter.ScryptParams(scryptParams.N, scryptParams.R, scryptParams.P);
        var newEncryptedEntries = new List<KeystoreFileWriter.EncryptedEntry>();

        foreach (var entry in _entries)
        {
            var secondaryPass = newSecondaryPass ?? entry.SecondaryPass;

            var tempFile = new KeystoreFile
            {
                ScryptSalt = Convert.ToBase64String(salt),
                ScryptN = scrypt.N,
                ScryptR = scrypt.R,
                ScryptP = scrypt.P
            };

            var key = ScryptKeyDeriver.DeriveFileKey(_mainPassword, entry.SecondaryPass, tempFile);

            var (nonce, ciphertext, tag) = AesGcmEncryptor.Encrypt(entry.Payload, key);
            var sig1 = SignData(ciphertext, _signer1);
            var sig2 = SignData(ciphertext, _signer2);

            newEncryptedEntries.Add(new KeystoreFileWriter.EncryptedEntry(nonce,ciphertext, tag, sig1, sig2));
        }

        var fileBytesToSign = SerializeKeystoreData(salt, scrypt, newEncryptedEntries);
        var finalSig1 = SignData(fileBytesToSign, newSigner1 ?? _signer1);
        var finalSig2 = SignData(fileBytesToSign, newSigner2 ?? _signer2);

        KeystoreFileWriter.WriteEntireKeystore(_keystorePath, salt, scrypt, newEncryptedEntries, finalSig1, finalSig2);

        Console.WriteLine("🔁 Keystore successfully re-encrypted and re-signed.");
    }

    private static byte[] SerializeKeystoreData(byte[] salt, KeystoreFileWriter.ScryptParams scrypt, List<KeystoreFileWriter.EncryptedEntry> entries)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write(Encoding.ASCII.GetBytes("SCAKSTR\x01"));
        writer.Write((ushort)salt.Length);
        writer.Write(salt);
        writer.Write(scrypt.N);
        writer.Write(scrypt.R);
        writer.Write(scrypt.P);
        writer.Write(entries.Count);

        foreach (var entry in entries)
        {
            writer.Write(entry.Nonce.Length);
            writer.Write(entry.Nonce);
            writer.Write(entry.Ciphertext.Length);
            writer.Write(entry.Ciphertext);
            writer.Write(entry.Tag.Length);
            writer.Write(entry.Tag);
            KeystoreSignatureBlock.Write(writer, entry.Signature1);
            KeystoreSignatureBlock.Write(writer, entry.Signature2);
        }

        return ms.ToArray();
    }

    private static byte[] SignData(byte[] data, AsymmetricKeyParameter privateKey)
    {
        var signer = new Org.BouncyCastle.Crypto.Signers.PssSigner(
            new Org.BouncyCastle.Crypto.Engines.RsaEngine(),
            new Org.BouncyCastle.Crypto.Digests.Sha256Digest(),
            20
        );
        signer.Init(true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public static string ExportCertificateToPem(X509Certificate cert)
    {
        using var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
        pemWriter.WriteObject(cert);
        pemWriter.Writer.Flush();
        return sw.ToString();
    }

    public static string ExportPrivateKeyToPem(AsymmetricKeyParameter privateKey)
    {
        using var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
        pemWriter.WriteObject(privateKey);
        pemWriter.Writer.Flush();
        return sw.ToString();
    }

    public record KeystoreSaveResult(byte[] Salt, KeystoreFileWriter.ScryptParams Params);

    public record AddKeystoreEntry(string Keystore, byte[] Payload, string SecondaryPass);
}
