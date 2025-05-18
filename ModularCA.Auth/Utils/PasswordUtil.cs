using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Auth.Utils
{
    public class PasswordUtil
    {
        private const string Lower = "abcdefghjkmnpqrstuvwxyz"; // no 'i', 'l'
        private const string Upper = "ABCDEFGHJKMNPQRSTUVWXYZ"; // no 'I', 'O'
        private const string Digits = "23456789"; // no '0', '1'
        private const string Symbols = "!@#$%^&*()-_=+";
        private const int SaltSize = 16; // 128 bits
        private const int Iterations = 100_000;
        private const int HashSize = 32; // 256 bits

        public static string Generate(int length = 16, bool includeSymbols = true)
        {
            if (length < 8) throw new ArgumentException("Password length must be at least 8");

            var charSets = new[]
            {
            Lower.ToCharArray(),
            Upper.ToCharArray(),
            Digits.ToCharArray(),
            includeSymbols ? Symbols.ToCharArray() : Array.Empty<char>()
        }.Where(set => set.Length > 0).ToList();

            var allChars = charSets.SelectMany(c => c).ToArray();
            if (allChars.Length == 0) throw new InvalidOperationException("No character sets selected.");

            var password = new char[length];
            using var rng = RandomNumberGenerator.Create();

            // Ensure one from each required set
            for (int i = 0; i < charSets.Count; i++)
            {
                password[i] = GetRandomChar(rng, charSets[i]);
            }

            // Fill the rest with random chars
            for (int i = charSets.Count; i < length; i++)
            {
                password[i] = GetRandomChar(rng, allChars);
            }

            // Shuffle to avoid predictable positions
            return new string(password.OrderBy(_ => GetRandomInt(rng)).ToArray());
        }

        private static char GetRandomChar(RandomNumberGenerator rng, char[] set)
        {
            return set[GetRandomInt(rng, set.Length)];
        }

        private static int GetRandomInt(RandomNumberGenerator rng, int max = int.MaxValue)
        {
            var buffer = new byte[4];
            rng.GetBytes(buffer);
            return Math.Abs(BitConverter.ToInt32(buffer, 0)) % max;
        }

        public static string HashPassword(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

            byte[] hash = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: Iterations,
                numBytesRequested: HashSize
            );

            return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
        }

        public static bool VerifyPassword(string password, string storedHash)
        {
            var parts = storedHash.Split('.');
            if (parts.Length != 3) return false;

            int iterations = int.Parse(parts[0]);
            byte[] salt = Convert.FromBase64String(parts[1]);
            byte[] expectedHash = Convert.FromBase64String(parts[2]);

            byte[] actualHash = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: iterations,
                numBytesRequested: expectedHash.Length
            );

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
    }
}
