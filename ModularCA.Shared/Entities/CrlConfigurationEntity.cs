using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("CrlConfigurations")]
public class CrlConfigurationEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = "default";

    [MaxLength(255)]
    public string Description { get; set; } = string.Empty;

    [Required]
    public TimeSpan Interval { get; set; } // e.g. every 7 days

    [Required]
    public TimeSpan OverlapPeriod { get; set; } // e.g. 1 hour of validity overlap

    public bool EnableDelta { get; set; }

    public TimeSpan? DeltaInterval { get; set; }

    public DateTime LastGenerated { get; set; }
}
