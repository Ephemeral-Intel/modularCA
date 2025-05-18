using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Entities
{
    public class CertificateAuthorityEntity
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        public Guid CertificateId { get; set; }

        [ForeignKey("CertificateId")]
        public virtual CertificateEntity Certificate { get; set; }

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;

        public bool IsRoot { get; set; } = false;

        public bool IsEnabled { get; set; } = true;

        // Optional future fields:
        // public CAType Type { get; set; } = CAType.Intermediate;
        // public Guid? ParentCAId { get; set; }
    }
}
