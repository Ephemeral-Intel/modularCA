using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Entities
{
    public class UserEntity
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(100)]
        public string Username { get; set; } = string.Empty;

        [MaxLength(255)]
        public string? Email { get; set; }

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [MaxLength(100)]
        public string? DisplayName { get; set; }

        public bool IsActive { get; set; } = true;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? LastLoginAt { get; set; }

        // Optional 2FA-related fields
        public string? TwoFactorSecret { get; set; }

        // Optional certificate-based login thumbprint
        public string? LoginCertificateThumbprint { get; set; }

        // === Relationships ===

        public virtual ICollection<UserRoleEntity> Roles { get; set; } = new List<UserRoleEntity>();

        public virtual ICollection<CertificateAccessListEntity> CertificateAccess { get; set; } = new List<CertificateAccessListEntity>();

        public virtual ICollection<CertificateAccessListEntity> GrantedAccess { get; set; } = new List<CertificateAccessListEntity>();
    }
}
