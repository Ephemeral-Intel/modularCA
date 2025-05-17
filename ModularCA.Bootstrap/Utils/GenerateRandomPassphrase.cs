using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Bootstrap.Utils
{
    public class GenerateRandomPassphrase
    {
        public static string Generate(int length = 14)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var data = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(data);
            var result = new char[length];
            for (int i = 0; i < length; i++)
                result[i] = chars[data[i] % chars.Length];
            return new string(result);
        }
    }
}
