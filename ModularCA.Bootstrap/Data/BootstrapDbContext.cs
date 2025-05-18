using System.Collections.Generic;
using System.Reflection.Emit;
using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Entities;

namespace ModularCA.Bootstrap.Data
{
    public class BootstrapDbContext(string connectionString) : DbContext
    {
        private readonly string _connectionString = connectionString;

        public DbSet<OIDOptionEntity> OIDOptions { get; set; } = null!;
        public DbSet<LdapConfigurationEntity> LdapConfigurations { get; set; } = null!;
        public DbSet<CertificateEntity> Certificates { get; set; } = null!;
        public DbSet<CertRequestEntity> CertificateRequests { get; set; } = null!;
        public DbSet<CrlEntity> Crls { get; set; } = null!;
        public DbSet<SigningProfileEntity> SigningProfiles { get; set; } = null!;
        public DbSet<FeatureFlagEntity> FeatureFlags{ get; set; } = null!;
        public DbSet<CrlConfigurationEntity> CrlConfigurations { get; set; } = null!;
        public DbSet<CertProfileEntity> CertProfiles { get; set; } = null!;
        public DbSet<KeystoreEntryEntity> Keystores { get; set; } = null!;
        public DbSet<CertificateAccessListEntity> CertificateAccessLists { get; set; } = null!;
        public DbSet<UserEntity> Users { get; set; } = null!;
        public DbSet<UserRoleEntity> UserRoles { get; set; } = null!;
        public DbSet<CertificateAuthorityEntity> CertificateAuthorities { get; set; } = null!;

        public DbSet<RefreshTokenEntity> RefreshTokens { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            options.UseMySql(_connectionString, ServerVersion.AutoDetect(_connectionString));

        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<CertificateAccessListEntity>()
                .HasOne(c => c.GrantedByUser)
                .WithMany(u => u.GrantedAccess)
                .HasForeignKey(c => c.GrantedByUserId);

            modelBuilder.Entity<CertificateAccessListEntity>()
                .HasOne(c => c.User)
                .WithMany(u => u.CertificateAccess)
                .HasForeignKey(c => c.UserId);
            modelBuilder.Entity<CertificateAccessListEntity>()
                .HasOne(c => c.GrantedByUser)
                .WithMany() // Or `.WithMany(u => u.CertificateAccessLists)` if a collection exists
                .HasForeignKey("GrantedByUserId"); // Replace with the actual foreign key property

        }
    }
}

