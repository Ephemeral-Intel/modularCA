using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Core.Utils;
using ModularCA.Shared.Models.CertProfiles;
using System;
using System.Linq;

namespace ModularCA.API.Controllers.v1.User
{
    [ApiController]
    [Route("api/v1/user/authorities")]
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

        [HttpGet("{serial}/file")]
        public async Task<IActionResult> GetCertificate(string serial)
        {
            var raw = await _certService.GetCertificateInfoAsync(serial);
            // Hide CA certs and System cert
            if (raw == null || raw.IsCA || raw.SubjectDN?.Contains("System Signing CA Certificate") == true)
                return NotFound();
            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-pem-file") || accept.Contains("application/pem-certificate-chain") || accept.Contains("pem"))
            {
                var certName = CertificateUtil.ParseCnFromPem(raw.Pem);
                var fileName = $"{certName}.pem";
                return File(raw.Pem, "application/x-pem-file", fileName);
            }
            else if (accept.Contains("application/x-x509-ca-cert") || accept.Contains("application/pkix-cert") || accept.Contains("der") || accept.Contains("application/octet-stream"))
            {
                var cert = CertificateUtil.ParseFromPem(raw.Pem);
                var cetName = CertificateUtil.ParseCnFromPem(raw.Pem);
                var fileName = $"{cetName}.cer";
                return File(cert.GetEncoded(), "application/x-x509-ca-cert", fileName);
            }
            return NotFound();
        }
    }

}
