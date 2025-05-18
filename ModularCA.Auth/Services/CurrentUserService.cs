using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Services
{
    public class CurrentUserService : ICurrentUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ModularCADbContext _db;
        private UserEntity? _user;
        private bool _loaded = false;

        public CurrentUserService(IHttpContextAccessor httpContextAccessor, ModularCADbContext db)
        {
            _httpContextAccessor = httpContextAccessor;
            _db = db;
        }

        public Guid? UserId
        {
            get
            {
                var httpUser = _httpContextAccessor.HttpContext?.User;

                var sub = httpUser?.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? httpUser?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

                return Guid.TryParse(sub, out var guid) ? guid : null;
            }
        }

        public bool IsAuthenticated => UserId != null;

        public UserEntity? User => _user;

        public async Task EnsureLoadedAsync()
        {
            if (_loaded || UserId == null) return;

            _user = await _db.Users
                .Include(u => u.Roles)
                .FirstOrDefaultAsync(u => u.Id == UserId && u.IsActive);

            _loaded = true;
        }
    }
}