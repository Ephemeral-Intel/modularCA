using ModularCA.Shared.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Auth.Interfaces
{
    public interface IJwtTokenService
    {
        (string Token, DateTime ExpiresAt) GenerateToken(UserEntity user, List<UserRoleEntity> roles);
        RefreshTokenEntity GenerateRefreshToken(Guid userId, string? ip);
    }
}
