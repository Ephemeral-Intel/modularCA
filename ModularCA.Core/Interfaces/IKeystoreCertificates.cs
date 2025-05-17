using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using ModularCA.Core.Models;

namespace ModularCA.Core.Interfaces;
public interface IKeystoreCertificates
{
    /// <summary>
    /// Returns all trusted CA certificates (public certs, no private keys).
    /// </summary>
    List<X509Certificate> GetTrustedAuthorities();

    /// <summary>
    /// Returns all signing-capable CA identities (must include private key).
    /// </summary>
    List<CertificateAuthorityIdentity> GetSigners();

    /// <summary>
    /// Attempts to retrieve the private key for the specified certificate.
    /// Returns null if not available.
    /// </summary>
    AsymmetricKeyParameter? GetPrivateKeyFor(X509Certificate cert);
}
