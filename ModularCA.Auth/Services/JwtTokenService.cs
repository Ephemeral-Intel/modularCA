using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Config;
using ModularCA.Core.Utils;
using ModularCA.Shared.Entities;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Auth.Services
{
    public class JwtTokenService : IJwtTokenService
    {
        private readonly Config _config;

        public JwtTokenService(Config config)
        {
            _config = config;
        }

        public (string Token, DateTime ExpiresAt) GenerateToken(UserEntity user, List<UserRoleEntity> roles)
        {
            var handler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config.JWT.Secret);
            var expires = DateTime.UtcNow.AddHours(2);

            var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim("username", user.Username)
        };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.Role.ToString()));
            }

            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expires,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256)
            };

            var token = handler.CreateToken(descriptor);
            return (handler.WriteToken(token), expires);
        }

        public RefreshTokenEntity GenerateRefreshToken(Guid userId, string? ip)
        {
            return new RefreshTokenEntity
            {
                UserId = userId,
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                CreatedByIp = ip,
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            };
        }
    }

}
