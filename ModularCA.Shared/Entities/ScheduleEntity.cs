using System.ComponentModel.DataAnnotations;

namespace ModularCA.Shared.Entities;

public class ScheduleEntity
{
    [Key]
    public int Id { get; set; }

    [Required]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string Type { get; set; } = string.Empty; // e.g. "CRL", "Email", "LDAP"

    [Required]
    public string CronExpression { get; set; } = string.Empty; // for future use

    public string PayloadJson { get; set; } = string.Empty; // task-specific config

    public bool Enabled { get; set; } = true;

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastRunUtc { get; set; }
    public DateTime? NextRunUtc { get; set; } // optional, can be used with Quartz later
}
