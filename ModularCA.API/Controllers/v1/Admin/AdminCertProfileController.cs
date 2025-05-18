using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Core.Services;
using ModularCA.Shared.Models.CertProfiles;

namespace ModularCA.API.Controllers.v1.Admin;

[ApiController]
[Route("api/v1/admin/cert-profiles")]
[AllowAnonymous]
//[Authorize(Roles = "CAAdmin,SuperAdmin")]
public class AdminCertProfileController(ICertProfileService certProfileService) : ControllerBase
{
    private readonly ICertProfileService _certProfileService = certProfileService;

    [HttpGet("list")]
    public async Task<IActionResult> GetAll()
    {
        var profiles = await _certProfileService.GetAllAsync();
        return Ok(profiles);
    }

    [HttpPost("create")]
    public async Task<IActionResult> Create([FromBody] CreateCertProfileRequest request)
    {
        var result = await _certProfileService.CreateAsync(request);
        return CreatedAtAction(nameof(GetAll), new { }, result);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateCertProfileRequest request)
    {
        await _certProfileService.UpdateAsync(id, request);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        await _certProfileService.DeleteAsync(id);
        return NoContent();
    }

    [HttpGet("{id}")]
    [AllowAnonymous] // or [Authorize(Roles = "Admin")] later
    public async Task<IActionResult> GetById(Guid id)
    {
        var profile = await _certProfileService.GetByIdAsync(id);
        if (profile == null)
            return NotFound(new { message = "Profile not found" });

        return Ok(profile);
    }

}
