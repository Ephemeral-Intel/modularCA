using ModularCA.Shared.Enums;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities
{
    [Table("CertificateAccess")]
    public class CertificateAccessListEntity
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public Guid CertificateId { get; set; }

        [ForeignKey("CertificateId")]
        public virtual CertificateEntity Certificate { get; set; }

        [Required]
        public Guid UserId { get; set; }

        [ForeignKey("UserId")]
        public virtual UserEntity User { get; set; }

        [Required]
        public CertificateAccessLevel AccessLevel { get; set; }

        public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

        public Guid? GrantedByUserId { get; set; }

        [ForeignKey("GrantedByUserId")]
        public virtual UserEntity GrantedByUser { get; set; }
    }
}
