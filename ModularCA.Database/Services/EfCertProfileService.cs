using System;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Entities;
using ModularCA.Core.Interfaces;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace ModularCA.Database.Services
{
    public class EfCertProfileService(ModularCADbContext db) : ICertProfileService
    {
        private readonly ModularCADbContext _db = db;

        public async Task<List<CertProfileDto>> GetAllAsync()
        {
            return await _db.CertProfiles
                .Select(p => new CertProfileDto
                {
                    Id = p.Id,
                    Name = p.Name,
                    Description = p.Description,
                    IsCaProfile = p.IsCaProfile,
                    IncludeRootInChain = p.IncludeRootInChain,
                    KeyUsage = p.KeyUsage,
                    ExtendedKeyUsage = p.ExtendedKeyUsage,
                    ValidityPeriod = p.ValidityPeriod
                })
                .ToListAsync();
        }

        public async Task<CertProfileDto> CreateAsync(CreateCertProfileRequest request)
        {
            var profile = new CertProfileEntity
            {
                Name = request.Name,
                Description = request.Description,
                IncludeRootInChain = request.IncludeRootInChain,
                IsCaProfile = request.IsCaProfile,
                KeyUsage = request.KeyUsage,
                ExtendedKeyUsage = request.ExtendedKeyUsage,
                ValidityPeriod = request.ValidityPeriod
            };

            _db.CertProfiles.Add(profile);
            await _db.SaveChangesAsync();

            return new CertProfileDto
            {
                Id = profile.Id,
                Name = profile.Name,
                Description = profile.Description,
                IsCaProfile = profile.IsCaProfile,
                IncludeRootInChain = profile.IncludeRootInChain,
                KeyUsage = profile.KeyUsage,
                ExtendedKeyUsage = profile.ExtendedKeyUsage,
                ValidityPeriod = profile.ValidityPeriod
            };
        }

        public async Task UpdateAsync(int id, UpdateCertProfileRequest request)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null) throw new KeyNotFoundException("Profile not found");

            profile.Name = request.Name;
            profile.Description = request.Description;
            profile.IsCaProfile = request.IsCaProfile;
            profile.IncludeRootInChain = request.IncludeRootInChain;
            profile.KeyUsage = request.KeyUsage;
            profile.ExtendedKeyUsage = request.ExtendedKeyUsage;
            profile.ValidityPeriod = request.ValidityPeriod;

            await _db.SaveChangesAsync();
        }

        public async Task DeleteAsync(int id)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null) return;

            _db.CertProfiles.Remove(profile);
            await _db.SaveChangesAsync();
        }
        public async Task<CertProfileDto?> GetByIdAsync(Guid id)
        {

            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null)
                return null;

            return new CertProfileDto
            {
                Id = profile.Id,
                Name = profile.Name,
                Description = profile.Description,
                IsCaProfile = profile.IsCaProfile,
                IncludeRootInChain = profile.IncludeRootInChain,
                KeyUsage = profile.KeyUsage,
                ExtendedKeyUsage = profile.ExtendedKeyUsage,
                ValidityPeriod = profile.ValidityPeriod
            };
        }
    }
}
