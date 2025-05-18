using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Database;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Ocsp;
using ModularCA.Core.Utils;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.ConstrainedExecution;

namespace ModularCA.API.Controllers.v1.User;


[ApiController]
[Route("api/v1/user/certificates")]
public class UserCertificateController(
    ICertificateStore certStore,
    ICertificateAuthority certAuthority
) : ControllerBase
{
    private readonly ICertificateStore _certStore = certStore;
    private readonly ICertificateAuthority _certAuthority = certAuthority;

    [HttpGet]
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

    [HttpGet("{serial}/file")]
    public async Task<IActionResult> GetCertificate(string serial)
    {
        var raw = await _certStore.GetCertificateInfoAsync(serial);
        // Hide CA certs and System cert
        if (raw == null || raw.IsCA || raw.SubjectDN?.Contains("System Signing CA Certificate") == true)
            return NotFound();
        var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
        
        if (accept.Contains("application/x-x509-ca-cert") || accept.Contains("application/pkix-cert") || accept.Contains("der") || accept.Contains("application/octet-stream"))
        {
            var cert = CertificateUtil.ParseFromPem(raw.Pem);
            var certName = CertificateUtil.ParseCnFromPem(raw.Pem);
            var fileName = $"{certName}.cer";
            return File(cert.GetEncoded(), "application/x-x509-ca-cert", fileName);
        }
        else 
        {
            var certName = CertificateUtil.ParseCnFromPem(raw.Pem);
            var fileName = $"{certName}.pem";
            return File(raw.Pem, "application/x-pem-file", fileName);
        }
    }

}

