using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Csr
{
    public class CreateCsrRequest
    {
        public string SubjectName { get; set; } = default!;  // e.g., "CN=example.com,O=ModularCA"
        public List<string>? SubjectAlternativeNames { get; set; } // optional SANs
        public string KeyAlgorithm { get; set; } = "RSA"; // or "ECDSA"

        public string SignatureAlgorithm { get; set; } = "SHA256withRSA"; // or "SHA256withECDSA"

        public string KeySize { get; set; } = "2048"; // or curve name for ECDSA

        public Guid SigningProfileId { get; set; }

        public Guid CertificateProfileId { get; set; }

    }
}
