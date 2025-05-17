using System;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto;
using ModularCA.Core.Interfaces;

namespace ModularCA.Core.Services
{
    public class CsrParserService : ICsrParserService
    {
        public Pkcs10CertificationRequest ParseFromPem(string pem)
        {
            try
            {
                using var reader = new StringReader(pem);
                var pemReader = new PemReader(reader);
                var obj = pemReader.ReadObject();

                if (obj is not Pkcs10CertificationRequest csr)
                    throw new InvalidOperationException("Invalid PEM input: expected a CSR");

                return csr;
            }
            catch (Exception ex)
            {
                throw new FormatException("Failed to parse CSR from PEM input", ex);
            }
        }

        public string ExtractSubject(Pkcs10CertificationRequest csr)
        {
            return csr.GetCertificationRequestInfo().Subject.ToString();
        }

        public AsymmetricKeyParameter ExtractPublicKey(Pkcs10CertificationRequest csr)
        {
            return csr.GetPublicKey();
        }
    }
}
