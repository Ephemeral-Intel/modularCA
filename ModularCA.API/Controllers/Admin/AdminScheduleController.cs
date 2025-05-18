using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Shared.Models.Crl;
using System;
using System.Threading.Tasks;

namespace ModularCA.API.Controllers.Admin
{
    [ApiController]
    [Route("api/admin/schedule")]
    //[Authorize(Roles = "CAAdmin,SuperAdmin")] // We aren't ready for this yet
    [AllowAnonymous]
    public class AdminScheduleController(ICrlConfigurationService crlConfigService) : ControllerBase
    {
        private readonly ICrlConfigurationService _crlConfigService = crlConfigService;

        // List all CRL scheduled jobs
        [HttpGet("crl")]
        public async Task<IActionResult> GetAll()
        {
            // You may want to return a list, adapt service as needed
            var jobs = await _crlConfigService.GetAllAsync();
            return Ok(jobs);
        }

        // Create a new CRL scheduled job
        [HttpPost("crl")]
        public async Task<IActionResult> Create([FromBody] CreateCrlConfigurationRequest request)
        {
            var job = await _crlConfigService.CreateAsync(request);
            return CreatedAtAction(nameof(GetById), new { id = job.Id }, job);
        }

        // Get a specific CRL scheduled job by ID
        [HttpGet("crl/{id:guid}")]
        public async Task<IActionResult> GetById(Guid id)
        {
            var job = await _crlConfigService.GetByIdAsync(id);
            if (job == null)
                return NotFound();
            return Ok(job);
        }

        // Update a CRL scheduled job
        [HttpPut("crl/{id:guid}")]
        public async Task<IActionResult> Update(Guid id, [FromBody] UpdateCrlConfigurationRequest request)
        {
            request.TaskId = id;
            await _crlConfigService.UpdateAsync(request);
            return NoContent();
        }

        // Enable a CRL scheduled job
        [HttpPost("crl/{id:guid}/enable")]
        public async Task<IActionResult> Enable(Guid id)
        {
            await _crlConfigService.SetEnabledAsync(id, true);
            return NoContent();
        }

        // Disable a CRL scheduled job
        [HttpPost("crl/{id:guid}/disable")]
        public async Task<IActionResult> Disable(Guid id)
        {
            await _crlConfigService.SetEnabledAsync(id, false);
            return NoContent();
        }

        // Delete a CRL scheduled job
        [HttpDelete("crl/{id:guid}")]
        public async Task<IActionResult> Delete(Guid id)
        {
            await _crlConfigService.DeleteAsync(id);
            return NoContent();
        }
    }
}
