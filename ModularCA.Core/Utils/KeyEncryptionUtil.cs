using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace ModularCA.Core.Utils
{
    public static class KeyEncryptionUtil
    {
        public static (byte[] aesKeyEncrypted, byte[] iv, byte[] encryptedPrivateKey) EncryptPrivateKey(
        AsymmetricKeyParameter rsaPublicKey,
        AsymmetricKeyParameter privateKey)
        {
            var privateKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetDerEncoded();

            // Generate 256-bit AES key
            var aesKey = new byte[32];
            var rng = new SecureRandom();
            rng.NextBytes(aesKey);

            // Generate 96-bit IV for AES-GCM
            var iv = new byte[12];
            rng.NextBytes(iv);

            // AES-GCM encrypt private key
            var gcm = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
            var keyParam = new KeyParameter(aesKey);
            var gcmParams = new AeadParameters(keyParam, 128, iv);

            gcm.Init(true, gcmParams);
            var output = new byte[gcm.GetOutputSize(privateKeyDer.Length)];
            var len = gcm.ProcessBytes(privateKeyDer, 0, privateKeyDer.Length, output, 0);
            gcm.DoFinal(output, len);

            // RSA-OAEP encrypt AES key
            var rsa = new OaepEncoding(new RsaEngine());
            rsa.Init(true, rsaPublicKey);
            var encryptedAesKey = rsa.ProcessBlock(aesKey, 0, aesKey.Length);

            return (encryptedAesKey, iv, output);
        }

        public static AsymmetricKeyParameter DecryptPrivateKey(
    byte[] encryptedAesKey,
    byte[] iv,
    byte[] encryptedPrivateKey,
    AsymmetricKeyParameter rsaPrivateKey)
        {
            // RSA decrypt AES key
            var rsa = new OaepEncoding(new RsaEngine());
            rsa.Init(false, rsaPrivateKey);
            var aesKey = rsa.ProcessBlock(encryptedAesKey, 0, encryptedAesKey.Length);

            // AES-GCM decrypt private key
            var gcm = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
            var keyParam = new KeyParameter(aesKey);
            var gcmParams = new AeadParameters(keyParam, 128, iv);

            gcm.Init(false, gcmParams);
            var output = new byte[gcm.GetOutputSize(encryptedPrivateKey.Length)];
            var len = gcm.ProcessBytes(encryptedPrivateKey, 0, encryptedPrivateKey.Length, output, 0);
            gcm.DoFinal(output, len);

            return PrivateKeyFactory.CreateKey(output);
        }

    }
}
