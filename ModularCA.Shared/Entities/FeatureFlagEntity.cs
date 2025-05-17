using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("FeatureFlags")]
public class FeatureFlagEntity
{
    [Key]
    public string Name { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    public string? Value { get; set; } // Optional value: port, email, interval, etc.

    public string? Description { get; set; } // Optional admin-friendly description
}
