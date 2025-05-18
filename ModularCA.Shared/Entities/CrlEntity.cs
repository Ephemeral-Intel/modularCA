using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("Crls")]
public class CrlEntity
{
    [Key]
    public Guid? Id { get; set; }
    public string IssuerName { get; set; } = string.Empty;
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    public int CrlNumber { get; set; }
    public bool IsDelta { get; set; }
    public string? PemData { get; set; } = string.Empty;
    public byte[] RawData { get; set; } = Array.Empty<byte>();
    public string? BaseCrlSerial { get; set; }
    public Guid TaskId { get; set; }

    [ForeignKey(nameof(TaskId))]

    public CrlConfigurationEntity? Task { get; set; }

    public DateTime ThisUpdate { get; set; }
    public DateTime NextUpdate { get; set; }
}
