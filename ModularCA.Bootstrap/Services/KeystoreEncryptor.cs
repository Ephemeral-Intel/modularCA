using ModularCA.Keystore.Crypto;
using System.Text;

namespace ModularCA.Bootstrap.Services;

public static class KeystoreEncryptor
{
    public record ScryptParams(int N, int R, int P);

    public static (
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] Tag,
    ScryptParams Params,
    byte[] Salt
) GenerateEncryptedKeystore(byte[] rawData, string mainPass, string secondaryPass)
    {
        int n = 1 << 15; // 32768
        int r = 8;
        int p = 1;
        byte[] salt = CryptoUtils.GenerateSalt(16);
        byte[] key = ScryptKeyDeriver.DeriveKey(mainPass, secondaryPass, n, r, p, salt);

        var (nonce, ciphertext, tag) = AesGcmEncryptor.Encrypt(rawData, key);

        return (nonce, ciphertext, tag, new ScryptParams(n, r, p), salt);
    }

}
