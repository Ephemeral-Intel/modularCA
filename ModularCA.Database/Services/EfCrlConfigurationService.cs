using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ModularCA.Core.Interfaces;
using ModularCA.Shared.Models.Crl;
using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Entities;

namespace ModularCA.Database.Services
{
    public class EfCrlConfigurationService(ModularCADbContext db) : ICrlConfigurationService
    {
        private readonly ModularCADbContext _db = db;

        public async Task<CrlConfigurationDto> GetAsync()
        {
            var config = await _db.CrlConfigurations.FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("CRL config not found.");

            return new CrlConfigurationDto
            {
                Id = config.TaskId,
                Name = config.Name,
                Description = config.Description,
                UpdateInterval = config.UpdateInterval,
                OverlapPeriod = config.OverlapPeriod,
                IsDelta = config.IsDelta,
                DeltaInterval = config.DeltaInterval,
                LastGenerated = config.LastGenerated
            };
        }

        public async Task UpdateAsync(UpdateCrlConfigurationRequest r)
        {
            var nextUpdate = NCrontab.CrontabSchedule.Parse(r.UpdateInterval)
                .GetNextOccurrence(DateTime.UtcNow);
            var config = await _db.CrlConfigurations
                .Where(c => c.TaskId == r.TaskId)
                .FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("CRL config not found.");

            config.Description = r.Description;
            config.UpdateInterval = r.UpdateInterval;
            config.OverlapPeriod = r.OverlapPeriod;
            config.IsDelta = r.IsDelta;
            config.DeltaInterval = r.DeltaInterval;
            config.NextUpdateUtc = nextUpdate;

            await _db.SaveChangesAsync();
        }

        public async Task<CrlConfigurationDto> CreateAsync(CreateCrlConfigurationRequest r)
        {
            var nextUpdate = NCrontab.CrontabSchedule.Parse(r.UpdateInterval)
                .GetNextOccurrence(DateTime.UtcNow);
            var config = new CrlConfigurationEntity
            {
                Name = r.Name,
                Description = r.Description,
                UpdateInterval = r.UpdateInterval,
                OverlapPeriod = r.OverlapPeriod,
                IsDelta = r.IsDelta,
                DeltaInterval = r.DeltaInterval,
                NextUpdateUtc = nextUpdate
            };
            _db.CrlConfigurations.Add(config);
            await _db.SaveChangesAsync();
            return new CrlConfigurationDto
            {
                Id = config.TaskId,
                Name = config.Name,
                Description = config.Description,
                UpdateInterval = config.UpdateInterval,
                OverlapPeriod = config.OverlapPeriod,
                IsDelta = config.IsDelta,
                DeltaInterval = config.DeltaInterval,
                LastGenerated = config.LastGenerated
            };
        }

        public async Task DeleteAsync(Guid id)
        {
            var config = await _db.CrlConfigurations
                .Where(c => c.TaskId == id)
                .FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("CRL config not found.");
            _db.CrlConfigurations.Remove(config);
            await _db.SaveChangesAsync();
        }

        public async Task SetEnabledAsync(Guid id, bool enabled)
        {
            var config = await _db.CrlConfigurations
                .Where(c => c.TaskId == id)
                .FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("CRL config not found.");
            config.Enabled = enabled;
            await _db.SaveChangesAsync();
        }

        public async Task<CrlConfigurationDto> GetByIdAsync(Guid id)
        {
            var config = await _db.CrlConfigurations
                .Where(c => c.TaskId == id)
                .FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("CRL config not found.");
            return new CrlConfigurationDto
            {
                Id = config.TaskId,
                Name = config.Name,
                Description = config.Description,
                UpdateInterval = config.UpdateInterval,
                OverlapPeriod = config.OverlapPeriod,
                IsDelta = config.IsDelta,
                DeltaInterval = config.DeltaInterval,
                LastGenerated = config.LastGenerated
            };
        }

        public async Task<IEnumerable<CrlConfigurationDto>> GetAllAsync()
        {
            var configs = await _db.CrlConfigurations.ToListAsync();
            return configs.Select(c => new CrlConfigurationDto
            {
                Id = c.TaskId,
                Name = c.Name,
                Description = c.Description,
                UpdateInterval = c.UpdateInterval,
                OverlapPeriod = c.OverlapPeriod,
                IsDelta = c.IsDelta,
                DeltaInterval = c.DeltaInterval,
                LastGenerated = c.LastGenerated
            }).ToList();
        }

    }

}
