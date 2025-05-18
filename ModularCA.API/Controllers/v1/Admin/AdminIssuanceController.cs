using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Utils;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Models.Revocation;
using System.Runtime.ConstrainedExecution;
using System.Text;

namespace ModularCA.API.Controllers.v1.Admin
{
    [ApiController]
    [Route("api/v1/admin/issue")]
    [AllowAnonymous] // Replace with [Authorize(Roles = "CAAdmin,SuperAdmin")] later

    public class AdminIssuanceController(
        ICertificateIssuanceService certificateIssuanceService) : ControllerBase
    {
        private readonly ICertificateIssuanceService _certificateIssuanceService = certificateIssuanceService;

        [HttpPost("pem")]
        public async Task<IActionResult> IssueCertificate([FromBody] IssueCertificateRequest req)
        {
            var cert = await _certificateIssuanceService.IssueCertificateAsync(req.CsrId, req.NotBefore, req.NotAfter, req.IncludeRoot);
            var certName = CertificateUtil.ParseCnFromPem(cert);
            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-x509-cert") || accept.Contains("application/pkix-cert") || accept.Contains("application/octet-stream") || accept.Contains(".der") || accept.Contains(".cer"))
            {
                var certDer = CertificateUtil.ParseFromPem(cert);
                var fileName = $"{certName}.cer";
                return File(certDer.GetEncoded(), "application/x-x509-cert", fileName);
            }
            else
            {
                var fileName = $"{certName}.pem";
                return File(Encoding.UTF8.GetBytes(cert), "application/x-pem-file", fileName);
            }
        }

        [HttpPost("reissue/certid")]
        public async Task<IActionResult> ReissueCertId([FromBody] ReissueCertificateRequestByCertId request)
        {
            var newCertPem = await _certificateIssuanceService.ReissueCertificateAsync(
                request.CertificateId,
                null,
                null,
                request.NotBefore,
                request.NotAfter,
                request.IncludeRoot);
            var certName = CertificateUtil.ParseCnFromPem(newCertPem);
            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-x509-cert") || accept.Contains("application/pkix-cert") || accept.Contains("application/octet-stream") || accept.Contains(".der") || accept.Contains(".cer"))
            {
                var certDer = CertificateUtil.ParseFromPem(newCertPem);
                var fileName = $"{certName}.cer";
                return File(certDer.GetEncoded(), "application/x-x509-cert", fileName);
            }
            else
            {
                var fileName = $"{certName}.pem";
                return File(Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", fileName);
            }
        }
        [HttpPost("reissue/certsn")]
        public async Task<IActionResult> ReissueCertSn([FromBody] ReissueCertificateRequestByCertSn request)
        {
            var newCertPem = await _certificateIssuanceService.ReissueCertificateAsync(
                null,
                request.SerialNumber,
                null,
                request.NotBefore,
                request.NotAfter,
                request.IncludeRoot);
            var certName = CertificateUtil.ParseCnFromPem(newCertPem);
            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-x509-cert") || accept.Contains("application/pkix-cert") || accept.Contains("application/octet-stream") || accept.Contains(".der") || accept.Contains(".cer"))
            {
                var certDer = CertificateUtil.ParseFromPem(newCertPem);
                var fileName = $"{certName}.cer";
                return File(certDer.GetEncoded(), "application/x-x509-cert", fileName);
            }
            else
            {
                var fileName = $"{certName}.pem";
                return File(Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", fileName);
            }
        }

        [HttpPost("reissue/csrid")]
        public async Task<IActionResult> ReissueCsrId([FromBody] ReissueCertificateRequestByCsrId request)
        {
            var newCertPem = await _certificateIssuanceService.ReissueCertificateAsync(
                null,
                null,
                request.CsrId,
                request.NotBefore,
                request.NotAfter,
                request.IncludeRoot);
            var certName = CertificateUtil.ParseCnFromPem(newCertPem);
            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-x509-cert") || accept.Contains("application/pkix-cert") || accept.Contains("application/octet-stream") || accept.Contains(".der") || accept.Contains(".cer"))
            {
                var certDer = CertificateUtil.ParseFromPem(newCertPem);
                var fileName = $"{certName}.cer";
                return File(certDer.GetEncoded(), "application/x-x509-cert", fileName);
            }
            else
            {
                var fileName = $"{certName}.pem";
                return File(Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", fileName);
            }
        }
    }
}
