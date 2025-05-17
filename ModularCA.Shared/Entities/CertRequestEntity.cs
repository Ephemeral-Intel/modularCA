using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("CertificateRequests")]
public class CertRequestEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public string CSR { get; set; } = string.Empty; // PEM-encoded string or raw base64

    [Required]
    [MaxLength(1024)]
    public string Subject { get; set; } = string.Empty; // Extracted from CSR

    [Required]
    public DateTime SubmittedAt { get; set; } = DateTime.UtcNow;

    [Required]
    [MaxLength(20)]
    public string Status { get; set; } = "Pending"; // Pending, Approved, Rejected

    public string KeyAlgorithm { get; set; } = string.Empty; // e.g., RSA, ECDSA

    public string KeySize { get; set; } = "2048"; // e.g., 2048, 4096

    public string SignatureAlgorithm { get; set; } = string.Empty; // e.g., SHA256WITHRSA

    public byte[]? EncryptedPrivateKey { get; set; } = null;
    public byte[]? AesKeyEncryptionIv { get; set; }

    public byte[]? EncryptedAesForPrivateKey { get; set; }

    public string? EncryptionCertSerialNumber { get; set; }

    public Guid? CertProfileId { get; set; }

    [ForeignKey("CertProfileId")]

    public CertProfileEntity CertProfile {  get; set; }

    public Guid? SigningProfileId { get; set; }

    [ForeignKey("SigningProfileId")]

    public SigningProfileEntity SigningProfile { get; set; }

    public Guid? IssuedCertificateId { get; set; }

    [ForeignKey(nameof(IssuedCertificateId))]
    public CertificateEntity? IssuedCertificate { get; set; }
}
