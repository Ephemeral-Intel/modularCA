using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ModularCA.Keystore.KeystoreFormat
{
    public class KeystoreFile
    {
        public string Type { get; set; } = "SCAKSTR";
        public string KeyAlg { get; set; } = "AES";
        public string Enc { get; set; } = "AES-256-GCM";
        public string ScryptSalt { get; set; }
        public int ScryptN { get; set; }
        public int ScryptR { get; set; }
        public int ScryptP { get; set; }

        public byte[]? FileSignature1 { get; set; }

        public byte[]? FileSignature2 { get; set; }

        public List<KeystoreEntry> Entries { get; set; } = new();

        public byte[] GetSaltBytes() => Convert.FromBase64String(ScryptSalt);

        public record KeystoreEntry(
            byte[] Nonce,
            byte[] Ciphertext,
            byte[] Tag,
            byte[]? Signature1,
            byte[]? Signature2);
    }
}
