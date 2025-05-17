using System.Linq;

namespace ModularCA.Core.Models
{
    public class CertificateInfoModel
    {
        public Guid CertificateId { get; set; } // <- Required for GET /cert/{id}
        public string Pem { get; set; } = string.Empty; // <- Required to return the PEM

        public string SubjectDN { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string? Thumbprints { get; set; } = string.Empty;

        public List<string> SubjectAlternativeNames { get; set; } = new();
        public List<string> KeyUsages { get; set; } = new();
        public List<string> ExtendedKeyUsages { get; set; } = new();

        public bool IsCA { get; set; }

        public byte[]? Iv { get; set; }
        public byte[]? EncryptedAesKey { get; set; }
        public byte[]? EncryptedPrivateKey { get; set; }

        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public bool Revoked { get; set; }
        public string RevocationReason { get; set; } = string.Empty;

        public DateTime? RevocationDate { get; set; }
        public Guid SigningProfileId { get; set; }
        public Guid CertProfileId { get; set; }

    }
}