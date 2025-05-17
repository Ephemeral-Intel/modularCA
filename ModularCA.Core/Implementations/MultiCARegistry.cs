using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;

namespace ModularCA.Core.Implementations
{
    public class MultiCARegistry(List<CertificateAuthorityIdentity> signers, List<X509Certificate> trusted) : IKeystoreCertificates
    {
        private readonly List<CertificateAuthorityIdentity> _signers = signers.ToList();
        private readonly List<X509Certificate> _trusted = trusted.ToList();

        public List<X509Certificate> GetTrustedAuthorities() => _trusted;

        public List<CertificateAuthorityIdentity> GetSigners() => _signers;

        public AsymmetricKeyParameter? GetPrivateKeyFor(X509Certificate cert)
        {
            return _signers.FirstOrDefault(s =>
                s.PublicCertificate.SerialNumber.Equals(cert.SerialNumber) &&
                s.PublicCertificate.SubjectDN.Equivalent(cert.SubjectDN))?.PrivateKey;
        }
    }
}