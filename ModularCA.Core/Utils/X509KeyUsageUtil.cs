using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Utils
{
    public static class X509KeyUsageUtil
    {
        public static int ParseKeyUsages(string usageCsv)
        {
            int flags = 0;
            foreach (var usage in usageCsv.Split(',').Select(u => u.Trim().ToLower()))
            {
                flags |= usage switch
                {
                    "digital signature" => X509KeyUsage.DigitalSignature,
                    "non repudiation" => X509KeyUsage.NonRepudiation,
                    "key encipherment" => X509KeyUsage.KeyEncipherment,
                    "data encipherment" => X509KeyUsage.DataEncipherment,
                    "key agreement" => X509KeyUsage.KeyAgreement,
                    "key cert sign" => X509KeyUsage.KeyCertSign,
                    "crl sign" => X509KeyUsage.CrlSign,
                    "encipher only" => X509KeyUsage.EncipherOnly,
                    "decipher only" => X509KeyUsage.DecipherOnly,
                    _ => 0
                };
            }
            return flags;
        }
    }
}
