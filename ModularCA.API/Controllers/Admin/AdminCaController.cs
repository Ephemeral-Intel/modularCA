using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Shared.Models.CertProfiles;
using System;
using System.Linq;

namespace ModularCA.API.Controllers.Admin
{
    [ApiController]
    [Route("api/admin/ca")]
    public class AdminCaController(ICertificateStore certService) : ControllerBase
    {
        private readonly ICertificateStore _certService = certService;

        [HttpGet("all")]
        public async Task<IActionResult> GetAllCaCertificates()
        {
            var certs = await _certService.GetAllCertificatesAsync();

            // Filter to CA certs only, if not already scoped
            var caCerts = certs
                .Where(c => c.IsCA) // assuming your ICertificateStore entries have IsCa boolean
                .ToList();

            return Ok(caCerts);
        }
    }

}
