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

namespace ModularCA.Functions.Services;

public class CrlService(ModularCADbContext dbContext, X509Certificate issuerCert, AsymmetricKeyParameter issuerKey, IFeatureFlagService features)
{
    private readonly ModularCADbContext _dbContext = dbContext;
    private readonly X509Certificate _issuerCert = issuerCert;
    private readonly AsymmetricKeyParameter _issuerKey = issuerKey;
    private readonly IFeatureFlagService _features = features;

    public async Task<byte[]> GenerateAndStoreCrlAsync(bool isDelta = false)
    {
        var now = DateTime.UtcNow;
        var nextUpdate = now.AddDays(7);

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(_issuerCert.SubjectDN);
        crlGen.SetThisUpdate(now);
        crlGen.SetNextUpdate(nextUpdate);

        var revokedCerts = await _dbContext.Certificates
            .Where(c => c.Revoked)
            .AsNoTracking()
            .ToListAsync();

        foreach (var cert in revokedCerts)
        {
            var reasonCode = GetCrlReasonCode(cert.RevocationReason);
            crlGen.AddCrlEntry(new BigInteger(cert.SerialNumber, 16), cert.ValidTo, reasonCode);
        }

        var latestCrlNumber = await _dbContext.Crls
            .Where(c => c.IssuerName == _issuerCert.SubjectDN.ToString())
            .OrderByDescending(c => c.CrlNumber)
            .Select(c => (int?)c.CrlNumber)
            .FirstOrDefaultAsync() ?? 0;

        var newCrlNumber = latestCrlNumber + 1;

        crlGen.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(newCrlNumber));

        var aki = new AuthorityKeyIdentifierStructure(_issuerCert);
        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, aki);

        if (isDelta)
        {
            crlGen.AddExtension(X509Extensions.DeltaCrlIndicator, true, new DerInteger(latestCrlNumber));
        }

        var signer = new Asn1SignatureFactory("SHA256WITHRSA", _issuerKey);
        var crl = crlGen.Generate(signer);
        var encoded = crl.GetEncoded();

        _dbContext.Crls.Add(new CrlEntity
        {
            CrlNumber = newCrlNumber,
            IsDelta = isDelta,
            RawData = encoded,
            GeneratedAt = now,
            IssuerName = _issuerCert.SubjectDN.ToString(),
            ThisUpdate = now,
            NextUpdate = nextUpdate
        });

        await _dbContext.SaveChangesAsync();

        return encoded;
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

    public async Task MaybeGenerateAsync()
    {
        if (!_features.IsEnabled("CRL.Enabled"))
            return;

        // proceed with CRL generation
    }
}
