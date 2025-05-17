using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Entities;

[Table("Keystores")]
public class KeystoreEntryEntity
{
    public int Id { get; set; }
    public string Name { get; set; } = default!;
    public string PassHash { get; set; } = default!;

    [Required]
    public byte[] Passblob { get; set; } = Array.Empty<byte>();
    public int ScryptN { get; set; }
    public int ScryptR { get; set; }
    public int ScryptP { get; set; }
    public string Salt { get; set; } = default!;
    public DateTime CreatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool Enabled { get; set; }
}
