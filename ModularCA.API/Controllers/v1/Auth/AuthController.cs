using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Models;
using ModularCA.Auth.Utils;
using System;
using ModularCA.Database;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using System.Threading.Tasks;

namespace ModularCA.API.Controllers.v1.Auth
{
    [ApiController]
    [Route("api/v1/auth")]
    public class AuthController : ControllerBase
    {
        private readonly ModularCADbContext _db;
        private readonly IJwtTokenService _jwt;
        private readonly ICurrentUserService _currentUser;

        public AuthController(ModularCADbContext db, IJwtTokenService jwt, ICurrentUserService currentUser)
        {
            _db = db;
            _jwt = jwt;
            _currentUser = currentUser;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] ModularCA.Auth.Models.LoginRequest request)
        {
            var user = _db.Users.FirstOrDefault(u => u.Username == request.Username);
            var roles = _db.UserRoles.Where(u => u.UserId == user.Id).ToList();


            if (user == null)
                return Unauthorized(new { error = "Invalid username or password" });
            var confirmPassword = PasswordUtil.VerifyPassword(request.Password, user.PasswordHash);
            if (!confirmPassword)
                return Unauthorized(new { error = "Invalid username or password" });

            var (Token, ExpiresAt) = _jwt.GenerateToken(user, roles); // expires in 15 min
            var refreshToken = _jwt.GenerateRefreshToken(user.Id, Request.HttpContext.Connection.RemoteIpAddress?.ToString());

            _db.RefreshTokens.Add(refreshToken);
            user.LastLoginAt = DateTime.UtcNow;
            _db.Users.Update(user);

            await _db.SaveChangesAsync();

            return Ok(new LoginResponse
            {
                Token = Token,
                ExpiresAt = ExpiresAt,
                RefreshToken = refreshToken.Token
            });
        }

        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            var stored = _db.RefreshTokens
                .Include(x => x.User)
                .FirstOrDefault(x => x.Token == request.RefreshToken && !x.IsRevoked);

            if (stored == null || stored.ExpiresAt < DateTime.UtcNow)
                return Unauthorized(new { error = "Invalid or expired refresh token" });

            var roles = _db.UserRoles.Where(u => u.UserId == stored.User.Id).ToList();

            var newAccessToken = _jwt.GenerateToken(stored.User, roles);
            var newRefreshToken = _jwt.GenerateRefreshToken(stored.UserId, HttpContext.Connection.RemoteIpAddress?.ToString());

            // Revoke old token
            stored.IsRevoked = true;
            stored.RevokedAt = DateTime.UtcNow;
            stored.ReplacedByToken = newRefreshToken.Token;

            _db.RefreshTokens.Add(newRefreshToken);
            _db.SaveChanges();

            return Ok(new LoginResponse
            {
                Token = newAccessToken.Token,
                ExpiresAt = newAccessToken.ExpiresAt,
                RefreshToken = newRefreshToken.Token
            });
        }
    }

}
