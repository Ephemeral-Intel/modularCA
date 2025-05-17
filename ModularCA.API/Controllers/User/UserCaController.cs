using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Shared.Models.CertProfiles;
using System;
using System.Linq;

namespace ModularCA.API.Controllers.User
{
    [ApiController]
    [Route("api/user/authorities")]
    public class UserCaController(ICertificateStore certService) : ControllerBase
    {
        private readonly ICertificateStore _certService = certService;

        [HttpGet]
        public async Task<IActionResult> GetValidCaCertificates()
        {
            var certs = await _certService.GetAllCertificatesAsync();

            // Filter to CA certs only, and exclude those with "System Signing CA Certificate" in SubjectDN
            var caCerts = certs
                .Where(c => c.IsCA && !(c.SubjectDN?.Contains("System Signing CA Certificate") ?? false))
                .ToList();

            return Ok(caCerts);
        }

        [HttpGet("{serial}")]
        public async Task<ActionResult<CertificateInfoModel>> GetCertificateInfo(string serial)
        {
            var cert = await _certService.GetCertificateInfoAsync(serial);
            if (cert == null)
                return NotFound();

            // Exclude and hide the System Signing CA Certificate from the response
            if (cert.SubjectDN?.Contains("System Signing CA Certificate") ?? false)
                return NotFound();

            return Ok(cert);
        }
    }

}
