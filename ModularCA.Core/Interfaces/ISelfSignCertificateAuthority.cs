using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using ModularCA.Core.Models;
using static ModularCA.Core.Implementations.SelfSignBouncyCastleCertificateAuthority;

namespace ModularCA.Core.Interfaces;

public interface ISelfSignCertificateAuthority
{
    CaKeyPair IssueSelfSignedCACertificate(CertificateRequestModel request);

}
