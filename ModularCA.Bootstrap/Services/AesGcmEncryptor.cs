using System.Security.Cryptography;

namespace ModularCA.Bootstrap.Services;

public static class AesGcmEncryptor
{
    public static (byte[] nonce, byte[] ciphertext, byte[] tag) Encrypt(byte[] data, byte[] key)
    {
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        var tag = new byte[16];
        var ciphertext = new byte[data.Length];

        using var aes = new AesGcm(key);
        aes.Encrypt(nonce, data, ciphertext, tag);

        return (nonce, ciphertext, tag);
    }

}
