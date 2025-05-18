using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Entities
{
    public class UserRoleEntity
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public Guid UserId { get; set; }

        [ForeignKey("UserId")]
        public virtual UserEntity User { get; set; }

        [Required]
        public RoleType Role { get; set; }

        // Optional: scope to a specific CA (null = global/system-wide)
        public Guid? CertificateAuthorityId { get; set; }

        [ForeignKey("CertificateAuthorityId")]
        public virtual CertificateAuthorityEntity? CertificateAuthority { get; set; }
    }
}
