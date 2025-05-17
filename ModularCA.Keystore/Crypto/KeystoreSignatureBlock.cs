using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Keystore.Crypto
{
    public static class KeystoreSignatureBlock
    {
        public static void Write(BinaryWriter writer, byte[]? sig)
        {
            if (sig == null)
            {
                writer.Write((ushort)0);
            }
            else
            {
                writer.Write((ushort)sig.Length);
                writer.Write(sig);
            }
        }
        public static byte[]? Read(BinaryReader reader)
        {
            ushort length = reader.ReadUInt16();
            return length > 0 ? reader.ReadBytes(length) : null;
        }
    }

}
