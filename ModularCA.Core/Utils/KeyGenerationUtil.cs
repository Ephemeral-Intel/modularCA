using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using System;

namespace ModularCA.Core.Utils;

public static class KeyGenerationUtil
{
    public static AsymmetricCipherKeyPair GenerateKeyPair(string algorithm, string keySizeOrCurve)
    {
        return algorithm.ToUpperInvariant() switch
        {
            "RSA" => GenerateRsaKeyPair(keySizeOrCurve),
            "ECDSA" => GenerateEcdsaKeyPair(keySizeOrCurve),
            _ => throw new ArgumentException($"Unsupported key algorithm: {algorithm}"),
        };
    }

    private static AsymmetricCipherKeyPair GenerateRsaKeyPair(string keySize)
    {
        int finalKeySize = keySize switch
        {
            "2048" => 2048,
            "4096" => 4096,
            _ => throw new ArgumentException($"Unsupported RSA key size: {keySize}")
        };
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), finalKeySize));
        return generator.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair GenerateEcdsaKeyPair(string curveBits)
    {
        string curveName = curveBits switch
        {
            "P-256" => "secp256r1",
            "P-384" => "secp384r1",
            "P-521" => "secp521r1",
            _ => throw new ArgumentException($"Unsupported curve bit size: {curveBits}")
        };

        X9ECParameters ecP = SecNamedCurves.GetByName(curveName);
        var ecDomain = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H);

        var generator = new ECKeyPairGenerator();
        var keyGenParams = new ECKeyGenerationParameters(ecDomain, new SecureRandom());
        generator.Init(keyGenParams);
        return generator.GenerateKeyPair();
    }
}
