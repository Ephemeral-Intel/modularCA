using System.Security.Cryptography;

namespace ModularCA.Keystore.Crypto;

public static class AesGcmDecryptor
{
    public static byte[] Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] key)
    {
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }

}