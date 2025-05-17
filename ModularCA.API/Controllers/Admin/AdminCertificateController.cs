using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Database;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Ocsp;

namespace ModularCA.Api.Controllers;

[ApiController]
[Route("api/admin/[controller]")]
public class AdminCertificateController(ICertificateStore certStore, ICertificateAuthority certAuthority) : ControllerBase
{
    private readonly ICertificateStore _certStore = certStore;
    private readonly ICertificateAuthority _certAuthority = certAuthority;

    [HttpGet("{serial}")]
    public async Task<ActionResult<CertificateInfoModel>> GetCertificateInfo(string serial)
    {
        var cert = await _certStore.GetCertificateInfoAsync(serial);
        if (cert == null)
        {
            return NotFound();
        }
        return Ok(cert);
    }

    [HttpGet("{serial}/pem")]
    public async Task<IActionResult> GetCertificatePem(string serial)
    {
        if (_certStore is not IRawCertificateStore rawStore)
        {
            return StatusCode(501, "Raw certificate access not implemented");
        }

        var raw = await rawStore.GetRawCertificateAsync(serial);
        if (raw == null || raw.Length == 0)
        {
            return NotFound();
        }

        var pem = Convert.ToBase64String(raw);
        var body = "-----BEGIN CERTIFICATE-----\n" +
                   string.Join("\n", Enumerable.Range(0, pem.Length / 64 + 1)
                       .Select(i => pem.Substring(i * 64, Math.Min(64, pem.Length - i * 64)))) +
                   "\n-----END CERTIFICATE-----";

        return Content(body, "application/x-pem-file");
    }

    [HttpPost("issue")]
    public async Task<IActionResult> IssueCertificate([FromBody] CertificateRequestModel request)
    {
        try
        {
            var certBytes = await _certAuthority.IssueCertificateAsync(request);

            var pem = Convert.ToBase64String(certBytes);
            var body = "-----BEGIN CERTIFICATE-----\n" +
                       string.Join("\n", Enumerable.Range(0, pem.Length / 64 + 1)
                           .Select(i => pem.Substring(i * 64, Math.Min(64, pem.Length - i * 64)))) +
                       "\n-----END CERTIFICATE-----";

            return Content(body, "application/x-pem-file");
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpPost("revoke")]
    public async Task<IActionResult> RevokeCertificate([FromQuery] string serial, [FromQuery] string reason = "unspecified")
    {
        try
        {
            var result = await _certAuthority.RevokeCertificateAsync(serial, reason);
            return result ? Ok() : NotFound();
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}
