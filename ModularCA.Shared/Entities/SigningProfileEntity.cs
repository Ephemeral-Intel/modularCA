using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("SigningProfiles")]
public class SigningProfileEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid(); // UUID primary key

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    public int? MaxPathLength { get; set; }

    // Comma-separated key usage flags (e.g., "digitalSignature,keyCertSign")
    public string KeyUsages { get; set; } = string.Empty;

    // Comma-separated OIDs for EKUs
    public string ExtendedKeyUsages { get; set; } = string.Empty;

    public string ValidityPeriodMin { get; set; } = "P47D";
    public string ValidityPeriodMax { get; set; } = "P1Y";
    public Guid CertProfileId { get; set; }

    [ForeignKey("CertProfileId")]
    public CertProfileEntity CertProfile { get; set; } = default!;
    public string SignatureAlgorithm { get; set; } = default!;

    public string KeyAlgorithm { get; set; } = default!;
    public string KeySize { get; set; } = default!;

    public bool IsDefault { get; set; } = false;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public int Revision { get; set; } = 0;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Guid? IssuerId { get; set; } // CA keypair ID or CA entity reference

    [ForeignKey("IssuerId")]
    public CertificateEntity Issuer { get; set; } = default!;
}
