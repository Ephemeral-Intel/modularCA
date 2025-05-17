using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Shared.Models.Crl;

namespace ModularCA.API.Controllers.Admin
{
    [ApiController]
    [Route("api/admin/crl")]
    [Authorize(Roles = "CAAdmin,SuperAdmin")]
    public class AdminCrlController(ICrlConfigurationService service) : ControllerBase
    {
        private readonly ICrlConfigurationService _service = service;

        [HttpGet]
        public async Task<IActionResult> Get() => Ok(await _service.GetAsync());

        [HttpPut]
        public async Task<IActionResult> Update([FromBody] UpdateCrlConfigurationRequest request)
        {
            await _service.UpdateAsync(request);
            return NoContent();
        }
    }

}
