using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Interfaces;

namespace ModularCA.Database.Services
{
    public class EfFeatureFlagService : IFeatureFlagService
    {
        private readonly ModularCADbContext _db;
        private readonly Dictionary<string, (bool Enabled, string? Value)> _cache;

        public EfFeatureFlagService(ModularCADbContext db)
        {
            _db = db;
            _cache = _db.FeatureFlags
                .AsNoTracking()
                .ToDictionary(f => f.Name, f => (f.Enabled, f.Value));
        }

        public bool IsEnabled(string flagName)
        {
            return _cache.TryGetValue(flagName, out var result) && result.Enabled;
        }

        public string? GetValue(string flagName)
        {
            return _cache.TryGetValue(flagName, out var result) ? result.Value : null;
        }

        public (bool Enabled, string? Value)? Get(string flagName)
        {
            return _cache.TryGetValue(flagName, out var result) ? result : null;
        }
    }
}
