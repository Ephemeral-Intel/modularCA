using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("OIDOptions")]
public class OIDOptionEntity
{
    [Key]
    public string OID { get; set; }

    [Required]
    [MaxLength(64)]
    public string FriendlyName { get; set; }

    public bool IsDefaultEntry { get; set; }

    public string KeyUsage { get; set; }
    public DateTime AddedOn { get; set; } = DateTime.UtcNow;

}
