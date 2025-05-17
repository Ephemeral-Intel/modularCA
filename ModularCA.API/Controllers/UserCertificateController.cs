using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Utilities.Collections;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Models.Issuance;

namespace ModularCA.API.Controllers;

[ApiController]
[Route("api/user")]
public class UserCertificateController : ControllerBase
{
    private readonly ICsrParserService _parser;
    private readonly ICertificateIssuanceService _issuer;
    private readonly ICertificateStore _store;

    public UserCertificateController(ICsrParserService parser, ICertificateIssuanceService issuer)
    {
        _parser = parser;
        _issuer = issuer;
    }

    /*[HttpPost("request")]
    public async Task<IActionResult> Submit([FromBody] SubmitCertificateRequest request)
    {
        // Parse and validate CSR
        var csr = _parser.ParseFromPem(request.CsrPem);

        // Issue certificate
        var cert = await _issuer.IssueCertificateAsync(csr, request.SigningProfileId);

        // Return issued certificate (PEM + metadata)
        return Ok(cert);
    }*/

    [HttpGet("cert/{id}")]
    public async Task<IActionResult> GetCertificateById([FromRoute] Guid id)
    {
        var cert = await _store.GetCertificateByIdAsync(id);
        if (cert == null)
            return NotFound(new { message = "Certificate not found." });

        return Ok(new
        {
            cert.CertificateId,
            cert.SubjectDN,
            cert.SerialNumber,
            cert.ValidFrom,
            cert.ValidTo,
            cert.Revoked,
            cert.RevocationReason,
            Pem = cert.Pem // Include this for immediate usage
        });
    }
}
