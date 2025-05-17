using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;

namespace ModularCA.Core.Interfaces
{
    public interface ICsrParserService
    {
        Pkcs10CertificationRequest ParseFromPem(string pem);
        string ExtractSubject(Pkcs10CertificationRequest csr);
        AsymmetricKeyParameter ExtractPublicKey(Pkcs10CertificationRequest csr);
    }
}
