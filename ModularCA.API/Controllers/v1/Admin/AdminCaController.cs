using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Core.Utils;
using ModularCA.Shared.Models.CertProfiles;
using System;
using System.Linq;

namespace ModularCA.API.Controllers.v1.Admin
{
    [ApiController]
    [Route("api/v1/admin/authorities")]
    public class AdminCaController(ICertificateStore certService, ICurrentUserService currentUser) : ControllerBase
    {
        private readonly ICertificateStore _certService = certService;
        private readonly ICurrentUserService _currentUser = currentUser;

        [HttpGet]
        [Authorize(Roles = "SuperAdmin,SystemAdmin,CAAdmin")]
        public async Task<IActionResult> GetValidCaCertificates()
        {
            await _currentUser.EnsureLoadedAsync();
            if(!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            var certs = await _certService.GetAllCertificatesAsync();

            // Filter to CA certs only, and exclude those with "System Signing CA Certificate" in SubjectDN
            var caCerts = certs
                .Where(c => c.IsCA && !(c.SubjectDN?.Contains("System Signing CA Certificate") ?? false))
                .ToList();

            return Ok(caCerts);
        }

        [HttpGet("include-system-ca")]
        [Authorize(Roles = "SuperAdmin,SystemAdmin,CAAdmin,Auditor")]
        public async Task<IActionResult> GetAllCaCertificates()
        {
            var certs = await _certService.GetAllCertificatesAsync();

            // Filter to CA certs only, and exclude those with "System Signing CA Certificate" in SubjectDN
            var caCerts = certs
                .Where(c => c.IsCA)
                .ToList();

            return Ok(caCerts);
        }

        [HttpGet("system-ca")]
        [Authorize(Roles = "SuperAdmin,SystemAdmin,CAAdmin,Auditor")]
        public async Task<IActionResult> GetSystemCaCertificates()
        {
            var certs = await _certService.GetAllCertificatesAsync();

            // Filter to CA certs only, and exclude those with "System Signing CA Certificate" in SubjectDN
            var caCerts = certs
                .Where(c => c.IsCA && (c.SubjectDN?.Contains("System Signing CA Certificate") ?? false))
                .ToList();

            return Ok(caCerts);
        }

        [HttpGet("{serial}")]
        [Authorize(Roles = "SuperAdmin,SystemAdmin,CAAdmin,Auditor")]
        public async Task<ActionResult<CertificateInfoModel>> GetCertificateInfo(string serial)
        {
            var cert = await _certService.GetCertificateInfoAsync(serial);
            if (cert == null)
                return NotFound();
            return Ok(cert);
        }

        [HttpGet("{serial}/file")]
        [Authorize(Roles = "SuperAdmin,SystemAdmin,CAAdmin,Auditor")]
        public async Task<IActionResult> GetCertificateFile(string serial)
        {
            var cert = await _certService.GetCertificateInfoAsync(serial);
            if (cert == null)
                return NotFound();

            var acceptHeader = Request.Headers["Accept"].ToString();
            if (acceptHeader.Contains("application/x-pem-file", StringComparison.OrdinalIgnoreCase) ||
                acceptHeader.Contains("text/plain", StringComparison.OrdinalIgnoreCase))
            {
                var certName = cert.SubjectDN.Split(',')[0].Trim();
                var fileName = certName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
                    ? certName.Substring(3).Trim()
                    : certName;
                return File(cert.Pem, "application/x-pem-file", fileName);
            }
            else if (acceptHeader.Contains("application/x-x509-ca-cert", StringComparison.OrdinalIgnoreCase) ||
                     acceptHeader.Contains("application/pkix-cert", StringComparison.OrdinalIgnoreCase) ||
                     acceptHeader.Contains("application/octet-stream", StringComparison.OrdinalIgnoreCase))
            {
                // Convert PEM to DER
                var certDer = CertificateUtil.ParseFromPem(cert.Pem);
                var certName = cert.SubjectDN.Split(',')[0].Trim();
                var fileName = certName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
                    ? certName.Substring(3).Trim()
                    : certName;
                return File(certDer.GetEncoded(), "application/x-x509-ca-cert", fileName);
            }
            else
            {
                // Default to PEM
                var certName = cert.SubjectDN.Split(',')[0].Trim();
                var fileName = certName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
                    ? certName.Substring(3).Trim()
                    : certName;
                return File(cert.Pem, "application/x-pem-file", fileName);
            }
        }
    }

}
