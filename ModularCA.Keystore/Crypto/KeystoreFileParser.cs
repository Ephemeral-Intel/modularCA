using System.Text;
using ModularCA.Keystore.KeystoreFormat;

namespace ModularCA.Keystore.Crypto
{
    public static class KeystoreFileParser
    {
        private const string MagicHeader = "SCAKSTR\x01";

        public static KeystoreFile Parse(string path)
        {
            var bytes = File.ReadAllBytes(path);
            var span = new ReadOnlySpan<byte>(bytes);

            // 1. Validate magic header
            var magic = Encoding.ASCII.GetString(span.Slice(0, 8));
            if (magic != MagicHeader)
                throw new InvalidDataException("Invalid keystore magic header.");

            int cursor = 8;

            // 2. Read salt length (ushort)
            ushort saltLength = BitConverter.ToUInt16(span.Slice(cursor, 2));
            cursor += 2;

            // 3. Read salt
            byte[] salt = span.Slice(cursor, saltLength).ToArray();
            cursor += saltLength;

            // 4. Read Scrypt params (N, r, p)
            int n = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
            int r = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
            int p = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;

            // 5. Read entry count
            int entryCount = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
            Console.WriteLine("Entry count: " + entryCount);

            var entries = new List<KeystoreFile.KeystoreEntry>();
            for (int i = 0; i < entryCount; i++)
            {
                int nonceLen = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
                byte[] nonce = span.Slice(cursor, nonceLen).ToArray();
                cursor += nonceLen;

                int cipherLen = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
                byte[] ciphertext = span.Slice(cursor, cipherLen).ToArray();
                cursor += cipherLen;

                int tagLen = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
                byte[] tag = span.Slice(cursor, tagLen).ToArray();
                cursor += tagLen;

                ushort sig1Len = BitConverter.ToUInt16(span.Slice(cursor, 2)); cursor += 2;
                byte[]? sig1 = sig1Len > 0 ? span.Slice(cursor, sig1Len).ToArray() : null;
                cursor += sig1Len;

                ushort sig2Len = BitConverter.ToUInt16(span.Slice(cursor, 2)); cursor += 2;
                byte[]? sig2 = sig2Len > 0 ? span.Slice(cursor, sig2Len).ToArray() : null;
                cursor += sig2Len;

                entries.Add(new KeystoreFile.KeystoreEntry(nonce, ciphertext, tag, sig1, sig2));
            }

            // 6. Read final file-wide signatures
            ushort finalSig1Len = BitConverter.ToUInt16(span.Slice(cursor, 2)); cursor += 2;
            byte[]? finalSig1 = finalSig1Len > 0 ? span.Slice(cursor, finalSig1Len).ToArray() : null;
            cursor += finalSig1Len;

            ushort finalSig2Len = BitConverter.ToUInt16(span.Slice(cursor, 2)); cursor += 2;
            byte[]? finalSig2 = finalSig2Len > 0 ? span.Slice(cursor, finalSig2Len).ToArray() : null;
            cursor += finalSig2Len;

            return new KeystoreFile
            {
                ScryptSalt = Convert.ToBase64String(salt),
                ScryptN = n,
                ScryptR = r,
                ScryptP = p,
                Entries = entries,
                FileSignature1 = finalSig1,
                FileSignature2 = finalSig2
            };
        }
    }
}
