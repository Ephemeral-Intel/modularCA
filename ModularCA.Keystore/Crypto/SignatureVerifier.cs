using System.Security.Cryptography;

namespace ModularCA.Keystore.Crypto;

public static class SignatureVerifier
{
    public static bool VerifyRsaSha256(byte[] content, byte[] signature, string pemPublicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pemPublicKey.ToCharArray());

        return rsa.VerifyData(
            content,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
    }
}
