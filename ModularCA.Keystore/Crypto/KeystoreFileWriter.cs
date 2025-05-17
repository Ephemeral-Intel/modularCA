using System.Text;
using ModularCA.Keystore.Secure;

namespace ModularCA.Keystore.Crypto;

public static class KeystoreFileWriter
{
    private static readonly byte[] MagicHeader = Encoding.ASCII.GetBytes("SCAKSTR\x01");

    public record ScryptParams(int N, int R, int P);

    public record EncryptedEntry(byte[] Nonce, byte[] Ciphertext, byte[] Tag, byte[]? Signature1, byte[]? Signature2);

    // Legacy initializer - can still be used for signature over header metadata if needed
    public static void CreateFile(
        string path,
        byte[] salt,
        ScryptParams scrypt,
        byte[]? signature1 = null,
        byte[]? signature2 = null)
    {
        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var writer = new BinaryWriter(stream);

        writer.Write(MagicHeader);
        writer.Write((ushort)salt.Length);
        writer.Write(salt);
        writer.Write(scrypt.N);
        writer.Write(scrypt.R);
        writer.Write(scrypt.P);

        KeystoreSignatureBlock.Write(writer, signature1);
        KeystoreSignatureBlock.Write(writer, signature2);
    }

    // NEW: Main keystore writer used by KeystoreService
    public static void WriteEntireKeystore(
    string path,
    byte[] salt,
    ScryptParams scrypt,
    List<EncryptedEntry> entries,
    byte[]? finalSig1 = null,
    byte[]? finalSig2 = null)
    {
        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var writer = new BinaryWriter(stream);

        writer.Write(MagicHeader);
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

        // Final file-wide signatures
        KeystoreSignatureBlock.Write(writer, finalSig1);
        KeystoreSignatureBlock.Write(writer, finalSig2);
    }

}
