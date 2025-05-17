using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Bootstrap.Services;

public static class CryptoUtils
{
    public static byte[] GenerateSalt(int length = 16)
    {
        var salt = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    public static string HashPass(string input)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hash);
    }
}
