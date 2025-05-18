using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Tls;
using ModularCA.Shared.Entities;
using System.Linq;

namespace ModularCA.Database;

public class ModularCADbContext(DbContextOptions<ModularCADbContext> options) : DbContext(options)
{
    public DbSet<CrlEntity> Crls { get; set; }
    public DbSet<LdapConfigurationEntity> LdapConfigurations { get; set; }
    public DbSet<CertProfileEntity> CertProfiles { get; set; }
    public DbSet<SigningProfileEntity> SigningProfiles { get; set; }
    public DbSet<CertRequestEntity> CertificateRequests { get; set; }
    public DbSet<CertificateEntity> Certificates { get; set; }
    public DbSet<KeystoreEntryEntity> Keystores { get; set; }
    public DbSet<OIDOptionEntity> OIDOptions { get; set; }
    
    public DbSet<FeatureFlagEntity> FeatureFlags { get; set; }
    public DbSet<CrlConfigurationEntity> CrlConfigurations { get; set; }

    public DbSet<CertificateAccessListEntity> CertificateAccessLists { get; set; }
    public DbSet<UserEntity> Users { get; set; }

    public DbSet<UserRoleEntity> UserRoles { get; set; }

    public DbSet<CertificateAuthorityEntity> CertificateAuthorities { get; set; }

    public DbSet<RefreshTokenEntity> RefreshTokens { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<CrlEntity>().HasIndex(c => new { c.IssuerName, c.CrlNumber }).IsUnique();
        modelBuilder.Entity<LdapConfigurationEntity>().HasIndex(s => s.Name).IsUnique();
        modelBuilder.Entity<CertProfileEntity>().HasIndex(c => c.Name).IsUnique();
        modelBuilder.Entity<SigningProfileEntity>().HasIndex(s => s.Name).IsUnique();
        modelBuilder.Entity<CertRequestEntity>(entity =>
        {
            entity.HasIndex(c => c.SubmittedAt);
            entity.HasOne(c => c.IssuedCertificate)
                  .WithMany()
                  .HasForeignKey(c => c.IssuedCertificateId)
                  .OnDelete(DeleteBehavior.SetNull);
        });
        modelBuilder.Entity<CertificateEntity>(c =>
        {
            c.HasIndex(c => c.SerialNumber).IsUnique();
            c.HasIndex(c => c.SubjectDN).IsUnique();
        });
        modelBuilder.Entity<KeystoreEntryEntity>().HasIndex(k => k.Name).IsUnique();
        modelBuilder.Entity<OIDOptionEntity>().HasIndex(o => o.OID).IsUnique();

        modelBuilder.Entity<FeatureFlagEntity>().HasIndex(f => f.Name).IsUnique();
        modelBuilder.Entity<CrlConfigurationEntity>().HasIndex(c =>c.Name).IsUnique();

        modelBuilder.Entity<CertificateAccessListEntity>()
        .HasIndex(x => new { x.UserId, x.CertificateId })
        .IsUnique();

        modelBuilder.Entity<CertificateAccessListEntity>()
            .HasOne(x => x.User)
            .WithMany(u => u.CertificateAccess)
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<CertificateAccessListEntity>()
            .HasOne(x => x.Certificate)
            .WithMany(c => c.AccessList)
            .HasForeignKey(x => x.CertificateId)
            .OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<UserRoleEntity>()
            .HasIndex(ur => new { ur.UserId, ur.Id })
            .IsUnique();
        modelBuilder.Entity<UserEntity>()
            .HasIndex(ur => ur.Username).IsUnique();
        modelBuilder.Entity<UserEntity>()
            .HasIndex(ur => ur.Id).IsUnique();
        modelBuilder.Entity<UserEntity>()
            .HasIndex(ur => ur.Email).IsUnique();
        modelBuilder.Entity<CertificateAuthorityEntity>()
            .HasIndex(ur => ur.Name).IsUnique();

        modelBuilder.Entity<CertificateAccessListEntity>()
        .HasOne(c => c.GrantedByUser)
        .WithMany() // Or `.WithMany(u => u.CertificateAccessLists)` if a collection exists
        .HasForeignKey("GrantedByUserId"); // Replace with the actual foreign key property


    }
}