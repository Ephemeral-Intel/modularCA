using ModularCA.Keystore.KeystoreFormat;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Utilities.Encoders;

namespace ModularCA.Keystore.Crypto;

public static class ScryptKeyDeriver
{
    public static byte[] DeriveKey(string mainPass, string secondaryPass, int N, int r, int p, byte[] salt)
    {
        var fullPass = Encoding.UTF8.GetBytes(mainPass + secondaryPass);
        return SCrypt.Generate(fullPass, salt, N, r, p, 32); // or desired key length
    }
    public static byte[] DeriveFileKey(string mainPass, string secondaryPass, KeystoreFile file)
    {
        var combined = Encoding.UTF8.GetBytes(mainPass + secondaryPass);
        var salt = Convert.FromBase64String(file.ScryptSalt);
        return SCrypt.Generate(combined, salt, file.ScryptN, file.ScryptR, file.ScryptP, 32);
    }


}