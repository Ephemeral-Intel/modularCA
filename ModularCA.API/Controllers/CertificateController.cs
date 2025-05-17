using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Database;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Ocsp;

namespace ModularCA.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateController(ICertificateStore certStore, ICertificateAuthority certAuthority) : ControllerBase
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

[ApiController]
[Route("api/[controller]")]
public class CrlController(ModularCADbContext dbContext) : ControllerBase
{
    private readonly ModularCADbContext _dbContext = dbContext;

    [HttpGet("{caName}.crl")]
    public async Task<IActionResult> GetLatestCrl(string caName)
    {
        var crl = await _dbContext.Crls
            .Where(c => c.IssuerName == caName && !c.IsDelta)
            .OrderByDescending(c => c.CrlNumber)
            .Select(c => c.RawData)
            .FirstOrDefaultAsync();

        if (crl == null)
        {
            return NotFound();
        }

        return File(crl, "application/pkix-crl", $"{caName}.crl");
    }

    [HttpGet("{caName}-delta.crl")]
    public async Task<IActionResult> GetLatestDeltaCrl(string caName)
    {
        var crl = await _dbContext.Crls
            .Where(c => c.IssuerName == caName && c.IsDelta)
            .OrderByDescending(c => c.CrlNumber)
            .Select(c => c.RawData)
            .FirstOrDefaultAsync();

        if (crl == null)
        {
            return NotFound();
        }

        return File(crl, "application/pkix-crl", $"{caName}-delta.crl");
    }

    [HttpPost("ocsp")]
    public async Task<IActionResult> HandleOcspRequest()
    {
        try
        {
            using var ms = new MemoryStream();
            await Request.Body.CopyToAsync(ms);
            var requestBytes = ms.ToArray();

            var ocspReq = new Org.BouncyCastle.Ocsp.OcspReq(requestBytes);
            var responses = new List<Org.BouncyCastle.Ocsp.CertificateStatus>();

            foreach (var id in ocspReq.GetRequestList())
            {
                var certId = id.GetCertID();
                var serialHex = certId.SerialNumber.ToString(16);

                var cert = await _dbContext.Certificates
                    .Where(c => c.SerialNumber == serialHex)
                    .AsNoTracking()
                    .FirstOrDefaultAsync();

                if (cert == null)
                {
                    responses.Add(new Org.BouncyCastle.Ocsp.UnknownStatus());
                }
                else if (cert.Revoked)
                {
                    responses.Add(new Org.BouncyCastle.Ocsp.RevokedStatus(cert.ValidTo, Org.BouncyCastle.Asn1.X509.CrlReason.PrivilegeWithdrawn));
                }
                else
                {
                    responses.Add(Org.BouncyCastle.Ocsp.CertificateStatus.Good);
                }
            }

            // Load the OCSP signing certificate and key
            var signerCert = await _dbContext.Certificates
                .Where(c => c.SubjectDN.Contains("OCSP") && !c.Revoked)
                .OrderByDescending(c => c.ValidTo)
                .FirstOrDefaultAsync();

            if (signerCert == null || signerCert.RawCertificate == null)
            {
                return StatusCode(500, "No OCSP signer certificate found");
            }

            var bcCert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(signerCert.RawCertificate);
            var privateKey = await System.IO.File.ReadAllTextAsync("ocsp.key.pem");
            var keyReader = new Org.BouncyCastle.OpenSsl.PemReader(new StringReader(privateKey));
            var keyObj = keyReader.ReadObject();
            var bcKey = keyObj is Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair ? pair.Private : (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)keyObj;

            // Construct and sign a basic OCSP response
            var responseGenerator = new BasicOcspRespGenerator(bcCert.GetPublicKey());

            int i = 0;
            foreach (var id in ocspReq.GetRequestList())
            {
                var certId = id.GetCertID();
                var certStatus = responses[i++];
                responseGenerator.AddResponse(certId, certStatus);
            }

            var basicResp = responseGenerator.Generate("SHA256WITHRSA", bcKey, new[] { bcCert }, DateTime.UtcNow);
            // Convert BasicOcspResp to ASN.1 response structure
            var asn1Resp = Org.BouncyCastle.Asn1.Ocsp.BasicOcspResponse.GetInstance(basicResp.GetEncoded());
            var ocspResp = new Org.BouncyCastle.Ocsp.OcspResp(new Org.BouncyCastle.Asn1.Ocsp.OcspResponse(
                new Org.BouncyCastle.Asn1.Ocsp.OcspResponseStatus(Org.BouncyCastle.Ocsp.OcspRespStatus.Successful),
                new Org.BouncyCastle.Asn1.Ocsp.ResponseBytes(
                    Org.BouncyCastle.Asn1.Ocsp.OcspObjectIdentifiers.PkixOcspBasic,
                    new Org.BouncyCastle.Asn1.DerOctetString(asn1Resp))
            ));
            var bytes = ocspResp.GetEncoded();


            return File(bytes, "application/ocsp-response");
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}
