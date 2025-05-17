using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Database;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Ocsp;
using ModularCA.Core.Utils;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.ConstrainedExecution;

namespace ModularCA.API.Controllers.User;


[ApiController]
[Route("api/user/certificate")]
public class UserCertificateController(
    ICertificateStore certStore,
    ICertificateAuthority certAuthority
) : ControllerBase
{
    private readonly ICertificateStore _certStore = certStore;
    private readonly ICertificateAuthority _certAuthority = certAuthority;

    [HttpGet("list")]
    public async Task<ActionResult<IEnumerable<CertificateInfoModel>>> ListCertificates()
    {
        var certs = await _certStore.ListAsync();
        
        // Filter to non-CA certs only
        var nonCaCerts = certs
            .Where(c => !c.IsCA && !(c.SubjectDN?.Contains("System Signing CA Certificate") ?? false))
            .ToList();
        
        return Ok(nonCaCerts);
    }

    [HttpGet("{serial}")]
    public async Task<ActionResult<CertificateInfoModel>> GetCertificateInfo(string serial)
    {
        var cert = await _certStore.GetCertificateInfoAsync(serial);
        if (cert == null)
            return NotFound();
        // Hide CA certs and System cert
        if (cert.IsCA || cert.SubjectDN?.Contains("System Signing CA Certificate") == true)
            return NotFound();
        return Ok(cert);
    }

    [HttpGet("{serial}/pem")]
    public async Task<IActionResult> GetCertificatePem(string serial)
    {
        var raw = await _certStore.GetCertificateInfoAsync(serial);
        // Hide CA certs and System cert
        if (raw == null || raw.IsCA || raw.SubjectDN?.Contains("System Signing CA Certificate") == true)
            return NotFound();
        if (raw != null)
        {
            return Content(raw.Pem, "application/x-pem-file");

        }
        return NotFound();
    }

}

