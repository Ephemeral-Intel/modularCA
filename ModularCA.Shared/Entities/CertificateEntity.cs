using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("Certificates")]
public class CertificateEntity
{
    [Key]
    public Guid CertificateId { get; set; }

    [Required]
    [MaxLength(64)]
    public string SerialNumber { get; set; } = string.Empty;

    public string Pem { get; set; } = string.Empty;
    
    
    [Required]
    [MaxLength(255)]
    public string SubjectDN { get; set; } = string.Empty;

    public string Issuer { get; set; } = string.Empty;

    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }

    public string SubjectAlternativeNamesJson { get; set; } = string.Empty;

    public string KeyUsagesJson { get; set; } = string.Empty;

    public string ExtendedKeyUsagesJson { get; set; } = string.Empty;

    public byte[]? EncryptedPrivateKey { get; set; }

    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }

    public string? Thumbprints { get; set; } = string.Empty;

    public bool IsCA { get; set; } = false;

    public bool Revoked { get; set; } = false;
    public string? RevocationReason { get; set; }
    public DateTime? RevocationDate { get; set; }

    public byte[]? RawCertificate { get; set; }

    public Guid? SigningProfileId { get; set; }

    [ForeignKey("SigningProfileId")]
    public SigningProfileEntity? SigningProfile { get; set; }
    public Guid? CertProfileId { get; set; }

    [ForeignKey("CertProfileId")]
    public CertProfileEntity? CertProfile { get; set; }

    public byte[]? AesKeyEncryptionIv { get; set; }

    public byte[]? EncryptedAesForPrivateKey { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /*public CertificateEntity() { }

    public CertificateEntity(byte[] rawData)
    {
        RawCertificate = rawData;
    }*/
}
