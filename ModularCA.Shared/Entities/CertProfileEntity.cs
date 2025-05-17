using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("CertProfiles")]
public class CertProfileEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid(); // UUID primary key

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(255)]
    public string Description { get; set; } = string.Empty;

    public bool IsCaProfile { get; set; }

    public bool IncludeRootInChain { get; set; } 

    [MaxLength(255)]
    public string KeyUsage { get; set; } = string.Empty;

    [MaxLength(255)]
    public string ExtendedKeyUsage { get; set; } = string.Empty;

    [MaxLength(50)]
    public string ValidityPeriod { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public int Revision { get; set; } = 0;

    public DateTime UpdatedAt {  get; set; } = DateTime.UtcNow;

    [Required]
    public bool CanBeDeleted { get; set; } = true;

    public string ProfileHash { get; set; } = string.Empty;

}
