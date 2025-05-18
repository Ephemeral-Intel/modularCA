using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Utils;
using ModularCA.Functions.Services;
using ModularCA.Shared.Models.Csr;

namespace ModularCA.API.Controllers.v1.User;

[ApiController]
[Route("api/v1/user/request")]
[AllowAnonymous] // Replace with [Authorize(Roles = "CAAdmin,SuperAdmin")] later
public class UserCertSignRequestController(
    ICsrService csrService
) : ControllerBase
{
    private readonly ICsrService _csrService = csrService;


    [HttpPost("generate")]
    public async Task<IActionResult> Generate([FromBody] CreateCsrRequest request)
    {
        var pem = await _csrService.GenerateCsrAsync(request);
        return Ok(new { csr = pem });
    }

    [HttpPost("upload")]
    public async Task<IActionResult> UploadCsrRequest([FromBody] UploadCsrRequest request)
    {
        _ = await _csrService.UploadCsrAsync(request.Pem, request.CertificateProfileId, request.SigningProfileId);
        return Ok();
    }

}
