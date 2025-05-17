using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Functions.Services;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.Issuance;

namespace ModularCA.API.Controllers.Admin;

[ApiController]
[Route("api/admin/csr")]
[AllowAnonymous] // Replace with [Authorize(Roles = "CAAdmin,SuperAdmin")] later
public class AdminCsrController(
    ICsrService csrService,
    ICertificateIssuanceService certificateIssuanceService
) : ControllerBase
{
    private readonly ICsrService _csrService = csrService;
    private readonly ICertificateIssuanceService _certificateIssuanceService = certificateIssuanceService;


    [HttpPost("generate")]
    public async Task<IActionResult> Generate([FromBody] CreateCsrRequest request)
    {
        var pem = await _csrService.GenerateCsrAsync(request);
        return Ok(new { csr = pem });
    }

    [HttpPost("issue")]
    public async Task<IActionResult> IssueCertificate([FromBody] IssueCertificateRequest req)
    {
        var cert = await _certificateIssuanceService.IssueCertificateAsync(req.CsrId, req.NotBefore, req.NotAfter, req.IncludeRoot);
        return File(Encoding.UTF8.GetBytes(cert), "application/x-pem-file", "issued-cert.pem");
    }

}
