using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Models.SigningProfiles;
using ModularCA.Core.Interfaces;
using ModularCA.Database.Services;

namespace ModularCA.API.Controllers.v1.Admin
{
    [ApiController]
    [Route("api/v1/admin/signing-profiles")]
    [AllowAnonymous]
    //[Authorize(Roles = "CAAdmin,SuperAdmin")]
    public class AdminSigningProfileController(ISigningProfileService service) : ControllerBase
    {
        private readonly ISigningProfileService _service = service;

        [HttpGet("list")]
        public async Task<IActionResult> GetAll()
        {
            var profiles = await _service.GetAllAsync();
            return Ok(profiles);
        }

        [HttpPost("create")]
        public async Task<IActionResult> Create([FromBody] CreateSigningProfileRequest r) =>
            CreatedAtAction(nameof(GetAll), new { }, await _service.CreateAsync(r));

        [HttpPut("{id}")]
        public async Task<IActionResult> Update(Guid id, [FromBody] UpdateSigningProfileRequest r)
        {
            await _service.UpdateAsync(id, r);
            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(Guid id)
        {
            await _service.DeleteAsync(id);
            return NoContent();
        }

        [HttpGet("{id}")]
        [AllowAnonymous] // or [Authorize(Roles = "Admin")] later
        public async Task<IActionResult> GetById(Guid id)
        {
            var profile = await _service.GetByIdAsync(id);
            if (profile == null)
                return NotFound(new { message = "Profile not found" });

            return Ok(profile);
        }

    }
}