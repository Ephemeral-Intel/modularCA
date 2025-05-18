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
            c.HasIndex(c => c.SubjectDN);
        });
        modelBuilder.Entity<KeystoreEntryEntity>().HasIndex(k => k.Name).IsUnique();
        modelBuilder.Entity<OIDOptionEntity>().HasIndex(o => o.OID).IsUnique();

        modelBuilder.Entity<FeatureFlagEntity>().HasIndex(f => f.Name).IsUnique();
        modelBuilder.Entity<CrlConfigurationEntity>().HasIndex(c =>c.Name).IsUnique();

    }
}