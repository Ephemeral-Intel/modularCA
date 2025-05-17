using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Models
{
    public record CertificateAuthorityIdentity(
    X509Certificate PublicCertificate,
    AsymmetricKeyParameter? PrivateKey
);
}
