using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("CrlConfigurations")]
public class CrlConfigurationEntity
{
    [Key]
    public Guid TaskId { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = "default";

    public bool Enabled { get; set; } = true;

    public string? IssuerDN { get; set; } = string.Empty;

    public Guid CaCertificateId { get; set; }
    [ForeignKey("CaCertificateId")]

    public CertificateEntity? CaCertificate { get; set; }

    public bool IsDelta { get; set; } = false;

    [MaxLength(255)]
    public string Description { get; set; } = string.Empty;

    [Required]
    public string UpdateInterval { get; set; } = string.Empty;

    public DateTime LastUpdatedUtc { get; set; } = DateTime.UtcNow;

    public DateTime NextUpdateUtc { get; set; } = DateTime.UtcNow.AddHours(1);

    [Required]
    public TimeSpan OverlapPeriod { get; set; } // e.g. 1 hour of validity overlap

    public string DeltaInterval { get; set; } = string.Empty;

    public DateTime LastGenerated { get; set; }
}
