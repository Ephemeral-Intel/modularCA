using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Shared.Entities;
using System.Text.Json;
using Org.BouncyCastle.Math;
using ModularCA.Database;
using System.Text;
using NCrontab;
using ModularCA.Shared.Models.Crl;
using ModularCA.Database.Services;

namespace ModularCA.Functions.Services;

public class CrlService : ICrlService
{
    private readonly ModularCADbContext _dbContext;
    private readonly IFeatureFlagService _features;
    private readonly IKeystoreCertificates _keystore;

    public CrlService(ModularCADbContext dbContext, IFeatureFlagService features, IKeystoreCertificates keystore)
    {
        _dbContext = dbContext;
        _features = features;
        _keystore = keystore;
    }

    public async Task<string> GenerateCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var ca = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == caCertificateId, cancellationToken);

        if (ca == null)
            throw new InvalidOperationException($"CA certificate {caCertificateId} not found.");
     
        // Get issuer cert and key from keystore
        var caPubKey = _keystore.GetTrustedAuthorities().Where(c => c.SubjectDN.ToString() == ca.SubjectDN).FirstOrDefault();
        if(caPubKey == null)
            throw new InvalidOperationException($"CA certificate {caCertificateId} not found in keystore.");
        var caPrivKey = _keystore.GetPrivateKeyFor(caPubKey);

        var crlJob = _dbContext.CrlConfigurations
            .Where(j => j.IssuerDN == caPubKey.IssuerDN.ToString())
            .FirstOrDefault();

        if (crlJob == null)
            throw new Exception("Could not find associated CRL scheduled job for CRL contruction");

        var now = DateTime.UtcNow;
        var ParsedUpdate = CrontabSchedule.Parse(crlJob.UpdateInterval);
        var nextUpdate = ParsedUpdate.GetNextOccurrence(now);

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(caPubKey.SubjectDN);
        crlGen.SetThisUpdate(now);
        crlGen.SetNextUpdate(nextUpdate);

        var revokedCerts = await _dbContext.Certificates
            .Where(c => c.Revoked && c.Issuer == caPubKey.SubjectDN.ToString())
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        foreach (var cert in revokedCerts)
        {
            var reasonCode = GetCrlReasonCode(cert.RevocationReason);
            crlGen.AddCrlEntry(new BigInteger(cert.SerialNumber, 16), cert.ValidTo, reasonCode);
        }

        var latestCrlNumber = await _dbContext.Crls
            .Where(c => c.IssuerName == caPubKey.SubjectDN.ToString())
            .OrderByDescending(c => c.CrlNumber)
            .Select(c => (int?)c.CrlNumber)
            .FirstOrDefaultAsync(cancellationToken) ?? 0;

        var newCrlNumber = latestCrlNumber + 1;

        crlGen.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(newCrlNumber));
        var aki = new AuthorityKeyIdentifierStructure(caPubKey);
        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, aki);

        var signer = new Asn1SignatureFactory("SHA256WITHRSA", caPrivKey);
        var crl = crlGen.Generate(signer);
        var encoded = crl.GetEncoded();

        if (_dbContext.Crls.Any(c => c.TaskId == crlJob.TaskId))
        {
            var updateCrl = await _dbContext.Crls
                .Where(c => c.TaskId == crlJob.TaskId)
                .FirstOrDefaultAsync(cancellationToken);
            updateCrl.NextUpdate = nextUpdate;
            updateCrl.RawData = encoded;
            updateCrl.GeneratedAt = now;
            updateCrl.CrlNumber = newCrlNumber;
            updateCrl.ThisUpdate = now;
            _dbContext.Crls.Update(updateCrl);
        }
        else
        {
            _dbContext.Crls.Add(new CrlEntity
            {
                CrlNumber = newCrlNumber,
                IsDelta = false,
                RawData = encoded,
                GeneratedAt = now,
                IssuerName = caPubKey.SubjectDN.ToString(),
                ThisUpdate = now,
                NextUpdate = nextUpdate,
                TaskId = crlJob.TaskId
            });
        }
        await _dbContext.SaveChangesAsync(cancellationToken);

        var UpdateCrlJob = _dbContext.CrlConfigurations
            .Where(j => j.TaskId == crlJob.TaskId)
            .FirstOrDefault();

        UpdateCrlJob.LastUpdatedUtc = DateTime.UtcNow;
        UpdateCrlJob.LastGenerated = DateTime.UtcNow;
        UpdateCrlJob.NextUpdateUtc = nextUpdate;

        await _dbContext.SaveChangesAsync(cancellationToken);

        // Return PEM
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN X509 CRL-----");
        sb.AppendLine(Convert.ToBase64String(encoded, Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine("-----END X509 CRL-----");
        return sb.ToString();
    }

    private static int GetCrlReasonCode(string reason)
    {
        return reason.ToLower() switch
        {
            "keycompromise" => CrlReason.KeyCompromise,
            "cacompromise" => CrlReason.CACompromise,
            "affiliationchanged" => CrlReason.AffiliationChanged,
            "superseded" => CrlReason.Superseded,
            "cessationofoperation" => CrlReason.CessationOfOperation,
            "certificatehold" => CrlReason.CertificateHold,
            _ => CrlReason.Unspecified
        };
    }

    public async Task<string?> GetLatestCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var ca = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == caCertificateId, cancellationToken);

        if (ca == null)
            return null;

        var issuerName = ca.Issuer;
        var crl = await _dbContext.Crls
            .Where(c => c.IssuerName == issuerName)
            .OrderByDescending(c => c.CrlNumber)
            .FirstOrDefaultAsync(cancellationToken);

        if (crl?.RawData == null)
            return null;

        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN X509 CRL-----");
        sb.AppendLine(Convert.ToBase64String(crl.RawData, Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine("-----END X509 CRL-----");
        return sb.ToString();
    }
}
