using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ModularCA.Core.Interfaces;
using ModularCA.Shared.Models.Crl;
using Microsoft.EntityFrameworkCore;

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
                Id = config.Id,
                Name = config.Name,
                Description = config.Description,
                Interval = config.Interval,
                OverlapPeriod = config.OverlapPeriod,
                EnableDelta = config.EnableDelta,
                DeltaInterval = config.DeltaInterval,
                LastGenerated = config.LastGenerated
            };
        }

        public async Task UpdateAsync(UpdateCrlConfigurationRequest r)
        {
            var config = await _db.CrlConfigurations.FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("CRL config not found.");

            config.Description = r.Description;
            config.Interval = r.Interval;
            config.OverlapPeriod = r.OverlapPeriod;
            config.EnableDelta = r.EnableDelta;
            config.DeltaInterval = r.DeltaInterval;

            await _db.SaveChangesAsync();
        }
    }

}
