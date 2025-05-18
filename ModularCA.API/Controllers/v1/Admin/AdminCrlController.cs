using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Utils;
using System;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.API.Controllers.v1.Admin
{
    [ApiController]
    [Route("api/v1/admin/crl")]
    [AllowAnonymous] // Replace with [Authorize(Roles = "CAAdmin,SuperAdmin")] when ready
    public class AdminCrlController(ICrlService crlService, ICertificateStore certStore) : ControllerBase
    {
        private readonly ICrlService _crlService = crlService;
        private readonly ICertificateStore _certStore = certStore;

        /// <summary>
        /// Get the latest CRL by CA certificate database ID (GUID), format based on Accept header.
        /// </summary>
        [HttpGet("by-id/{caId:guid}")]
        public async Task<IActionResult> GetCrlByCaId(Guid caId)
        {
            var cert = await _certStore.GetCertificateByIdAsync(caId);
            if (cert == null)
                return NotFound("CA certificate not found for the specified serial number.");
            if (!cert.IsCA)
                return BadRequest("The specified certificate is not a CA certificate.");

            var crl = await _crlService.GetLatestCrlAsync(caId);
            if (crl == null)
                return NotFound("No CRL found for the specified CA certificate ID.");

            var cnPart = cert.SubjectDN.Split(',')[0].Trim();
            var crlName = cnPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? cnPart.Substring(3).Trim() : cnPart;

            var accept = Request.Headers["Accept"].ToString();
            if (accept.Contains("application/pkix-crl", StringComparison.OrdinalIgnoreCase))
            {
                var crlDer = CertificateUtil.ParseCrlFromPem(crl);
                var fileName = $"{crlName}.crl";
                return File(crlDer, "application/pkix-crl", fileName);
            }
            else // Default to PEM
            {
                var fileName = $"{crlName}-crl.pem";
                return File(Encoding.UTF8.GetBytes(crl), "application/x-pem-file", fileName);
            }
        }

        /// <summary>
        /// Get the latest CRL by CA certificate serial number, format based on Accept header.
        /// </summary>
        [HttpGet("by-serial/{serial}")]
        public async Task<IActionResult> GetCrlByCaSerial(string serial)
        {
            var cert = await _certStore.GetCertificateInfoAsync(serial);
            if (cert == null)
                return NotFound("CA certificate not found for the specified serial number.");
            if (!cert.IsCA)
                return BadRequest("The specified certificate is not a CA certificate.");

            var crl = await _crlService.GetLatestCrlAsync(cert.CertificateId);
            if (crl == null)
                return NotFound("No CRL found for the specified CA certificate serial number.");

            var cnPart = cert.SubjectDN.Split(',')[0].Trim();
            var crlName = cnPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? cnPart.Substring(3).Trim() : cnPart;

            var accept = Request.Headers["Accept"].ToString();
            if (accept.Contains("application/pkix-crl", StringComparison.OrdinalIgnoreCase))
            {
                var crlDer = CertificateUtil.ParseCrlFromPem(crl);
                var fileName = $"{crlName}.crl";
                return File(crlDer, "application/pkix-crl", fileName);
            }
            else // Default to PEM
            {
                var fileName = $"{crlName}-crl.pem";
                return File(Encoding.UTF8.GetBytes(crl), "application/x-pem-file", fileName);
            }
        }
    }
}
