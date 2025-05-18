using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Shared.Models.Revocation;
using ModularCA.Shared.Models.Issuance;

namespace ModularCA.API.Controllers.v1.Admin;

[ApiController]
[Route("api/v1/admin/revocation")]
[AllowAnonymous] // Replace with [Authorize(Roles = "CAAdmin,SuperAdmin")] as needed
public class AdminRevocationController(
    ICertificateRevocationService revocationService
) : ControllerBase
{
    private readonly ICertificateRevocationService _revocationService = revocationService;

    [HttpPost("revoke/certid")]
    public async Task<IActionResult> Revoke([FromBody] RevokeCertificateRequestByCertId request)
    {
        await _revocationService.RevokeCertificateAsync(request.CertificateId, null, request.Reason);
        return Ok(new { message = "Certificate revoked." });
    }

    [HttpPost("revoke/certsn")]
    public async Task<IActionResult> Revoke([FromBody] RevokeCertificateRequestByCertSerial request)
    {
        await _revocationService.RevokeCertificateAsync(null, request.SerialNumber, request.Reason);
        return Ok(new { message = "Certificate revoked." });
    }

}
