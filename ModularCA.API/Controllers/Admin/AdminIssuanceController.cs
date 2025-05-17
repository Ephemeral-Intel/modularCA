using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Models.Revocation;
using System.Text;

namespace ModularCA.API.Controllers.Admin
{
    [ApiController]
    [Route("api/admin/issue")]
    [AllowAnonymous] // Replace with [Authorize(Roles = "CAAdmin,SuperAdmin")] later

    public class AdminIssuanceController(
        ICertificateIssuanceService certificateIssuanceService) : ControllerBase
    {
        private readonly ICertificateIssuanceService _certificateIssuanceService = certificateIssuanceService;

        [HttpPost]
        public async Task<IActionResult> IssueCertificate([FromBody] IssueCertificateRequest req)
        {
            var cert = await _certificateIssuanceService.IssueCertificateAsync(req.CsrId, req.NotBefore, req.NotAfter, req.IncludeRoot);
            return File(Encoding.UTF8.GetBytes(cert), "application/x-pem-file", "issued-cert.pem");
        }

        [HttpPost("reissue/certid")]
        public async Task<IActionResult> ReissueCertId([FromBody] ReissueCertificateRequestByCertId request)
        {
            // Reissue by resigning the original CSR (or a new one if provided)
            var newCertPem = await _certificateIssuanceService.ReissueCertificateAsync(
                request.CertificateId,
                null,
                null,
                request.NotBefore,
                request.NotAfter,
                request.IncludeRoot);
            return File(System.Text.Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", "reissued-cert.pem");
        }
        [HttpPost("reissue/certsn")]
        public async Task<IActionResult> ReissueCertSn([FromBody] ReissueCertificateRequestByCertSn request)
        {
            // Reissue by resigning the original CSR (or a new one if provided)
            var newCertPem = await _certificateIssuanceService.ReissueCertificateAsync(
                null,
                request.SerialNumber,
                null,
                request.NotBefore,
                request.NotAfter,
                request.IncludeRoot);
            return File(System.Text.Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", "reissued-cert.pem");
        }

        [HttpPost("reissue/csrid")]
        public async Task<IActionResult> ReissueCsrId([FromBody] ReissueCertificateRequestByCsrId request)
        {
            // Reissue by resigning the original CSR (or a new one if provided)
            var newCertPem = await _certificateIssuanceService.ReissueCertificateAsync(
                null,
                null,
                request.CsrId,
                request.NotBefore,
                request.NotAfter,
                request.IncludeRoot);
            return File(System.Text.Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", "reissued-cert.pem");
        }

    }
}
