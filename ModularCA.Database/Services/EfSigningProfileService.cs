using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.SigningProfiles;
using ModularCA.Core.Interfaces;
using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Models.CertProfiles;

namespace ModularCA.Database.Services
{
    public class EfSigningProfileService(ModularCADbContext db) : ISigningProfileService
    {
        private readonly ModularCADbContext _db = db;

        public async Task<List<SigningProfileDto>> GetAllAsync() =>
            await _db.SigningProfiles
                .Select(x => new SigningProfileDto
                {
                    Id = x.Id,
                    Name = x.Name,
                    Description = x.Description,
                    SignatureAlgorithm = x.SignatureAlgorithm,
                    KeySize = x.KeySize,
                    ValidityPeriodMin = x.ValidityPeriodMin,
                    ValidityPeriodMax = x.ValidityPeriodMax,
                    IsDefault = x.IsDefault
                })
                .ToListAsync();

        public async Task<SigningProfileDto> CreateAsync(CreateSigningProfileRequest r)
        {
            var entity = new SigningProfileEntity
            {
                Name = r.Name,
                Description = r.Description,
                SignatureAlgorithm = r.SignatureAlgorithm,
                ValidityPeriodMin = r.ValidityPeriodMin,
                ValidityPeriodMax = r.ValidityPeriodMax,
                IsDefault = r.IsDefault
            };

            _db.SigningProfiles.Add(entity);
            await _db.SaveChangesAsync();

            return new SigningProfileDto
            {
                Id = entity.Id,
                Name = entity.Name,
                Description = entity.Description,
                SignatureAlgorithm = entity.SignatureAlgorithm,
                ValidityPeriodMin = r.ValidityPeriodMin,
                ValidityPeriodMax = r.ValidityPeriodMax,
                IsDefault = entity.IsDefault
            };
        }

        public async Task UpdateAsync(Guid id, UpdateSigningProfileRequest r)
        {
            var entity = await _db.SigningProfiles.FindAsync(id);
            if (entity == null) throw new KeyNotFoundException();

            entity.Name = r.Name;
            entity.Description = r.Description;
            entity.SignatureAlgorithm = r.SignatureAlgorithm;
            entity.ValidityPeriodMin = r.ValidityPeriodMin;
            entity.ValidityPeriodMax = r.ValidityPeriodMax;
            entity.IsDefault = r.IsDefault;

            await _db.SaveChangesAsync();
        }

        public async Task DeleteAsync(Guid id)
        {
            var entity = await _db.SigningProfiles.FindAsync(id);
            if (entity != null)
            {
                _db.SigningProfiles.Remove(entity);
                await _db.SaveChangesAsync();
            }
        }

        public async Task<SigningProfileDto?> GetByIdAsync(Guid id)
        {

            var entity = await _db.SigningProfiles.FindAsync(id);
            if (entity == null)
                return null;

            return new SigningProfileDto
            {
                Id = entity.Id,
                Name = entity.Name,
                Description = entity.Description,
                SignatureAlgorithm = entity.SignatureAlgorithm,
                ValidityPeriodMin = entity.ValidityPeriodMin,
                ValidityPeriodMax = entity.ValidityPeriodMax,
                IsDefault = entity.IsDefault,
            };
        }

        public async Task<string> GetValidityMinimum(Guid id)
        {
            var entity = await _db.SigningProfiles
                .Where(o => o.Id == id)
                .Select(o => o.ValidityPeriodMin)
                .ToListAsync();

            return entity[0];
        }

        public async Task<string> GetValidityMaximum(Guid id)
        {
            var entity = await _db.SigningProfiles
                .Where(o => o.Id == id)
                .Select(o => o.ValidityPeriodMax)
                .ToListAsync();

            return entity[0];
        }
    }
}