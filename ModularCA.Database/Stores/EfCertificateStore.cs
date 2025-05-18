using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Shared.Entities;
using System.Text.Json;
using System.Linq;
using ModularCA.Shared.Models.CertProfiles;

namespace ModularCA.Database.Stores;

public class EfCertificateStore(ModularCADbContext dbContext) : ICertificateStore
{
    private readonly ModularCADbContext _dbContext = dbContext;

    public async Task SaveCertificateAsync(
        byte[] certificateBytes,
        CertificateInfoModel info,
        byte[]? encryptedPrivateKey = null)
    {
        var entity = new CertificateEntity
        {
            SerialNumber = info.SerialNumber,
            SubjectDN = info.SubjectDN,
            Pem = info.Pem,
            Issuer = info.Issuer,
            NotBefore = info.NotBefore,
            NotAfter = info.NotAfter,
            Thumbprints = info.Thumbprints,
            IsCA = info.IsCA,
            ValidFrom = info.ValidFrom,
            ValidTo = info.ValidTo,
            Revoked = info.Revoked,
            RevocationReason = info.RevocationReason,
            RevocationDate = info.RevocationDate,
            CertProfileId = info.CertProfileId,
            SigningProfileId = info.SigningProfileId,
            SubjectAlternativeNamesJson = JsonSerializer.Serialize(info.SubjectAlternativeNames),
            KeyUsagesJson = JsonSerializer.Serialize(info.KeyUsages),
            ExtendedKeyUsagesJson = JsonSerializer.Serialize(info.ExtendedKeyUsages),
            RawCertificate = certificateBytes,
            AesKeyEncryptionIv = info.Iv,
            EncryptedAesForPrivateKey = info.EncryptedAesKey,
            EncryptedPrivateKey = info.EncryptedPrivateKey
        };

        _dbContext.Certificates.Add(entity);
        await _dbContext.SaveChangesAsync();
    }

    public async Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber)
    {
        var entity = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.SerialNumber == serialNumber);

        if (entity == null) return null;

        return new CertificateInfoModel
        {
            Pem = entity.Pem,
            CertificateId = entity.CertificateId,
            SerialNumber = entity.SerialNumber,
            SubjectDN = entity.SubjectDN,
            Issuer = entity.Issuer,
            NotBefore = entity.NotBefore,
            NotAfter = entity.NotAfter,
            Thumbprints = entity.Thumbprints,
            IsCA = entity.IsCA,
            ValidFrom = entity.ValidFrom,
            ValidTo = entity.ValidTo,
            Revoked = entity.Revoked,
            RevocationReason = entity.RevocationReason ?? string.Empty,
            RevocationDate = entity.RevocationDate,
            SigningProfileId = entity.SigningProfileId ?? Guid.Empty,
            SubjectAlternativeNames = string.IsNullOrWhiteSpace(entity.SubjectAlternativeNamesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(entity.SubjectAlternativeNamesJson)!,

            KeyUsages = string.IsNullOrWhiteSpace(entity.KeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(entity.KeyUsagesJson)!,

            ExtendedKeyUsages = string.IsNullOrWhiteSpace(entity.ExtendedKeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(entity.ExtendedKeyUsagesJson)!,

        };
    }

    public async Task<IEnumerable<CertificateInfoModel>> ListAsync()
    {
        var entities = await _dbContext.Certificates.AsNoTracking().ToListAsync();

        return entities.Select(c => new CertificateInfoModel
        {
            CertificateId = c.CertificateId,
            SerialNumber = c.SerialNumber,
            SubjectDN = c.SubjectDN,
            Issuer = c.Issuer,
            NotBefore = c.NotBefore,
            NotAfter = c.NotAfter,
            Thumbprints = c.Thumbprints,
            IsCA = c.IsCA,
            ValidFrom = c.ValidFrom,
            ValidTo = c.ValidTo,
            Revoked = c.Revoked,
            RevocationReason = c.RevocationReason,
            RevocationDate = c.RevocationDate,
            SigningProfileId = c.SigningProfileId ?? Guid.Empty,
            SubjectAlternativeNames = string.IsNullOrWhiteSpace(c.SubjectAlternativeNamesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.SubjectAlternativeNamesJson)!,

            KeyUsages = string.IsNullOrWhiteSpace(c.KeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.KeyUsagesJson)!,

            ExtendedKeyUsages = string.IsNullOrWhiteSpace(c.ExtendedKeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.ExtendedKeyUsagesJson)!,

        });
    }

    public async Task<CertificateInfoModel?> GetCertificateBySerialNumberAsync(string serialNumber)
    {
        var entity = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.SerialNumber == serialNumber);
        if (entity == null) return null;
        return new CertificateInfoModel
        {
            Pem = entity.Pem,
            CertificateId = entity.CertificateId,
            SerialNumber = entity.SerialNumber,
            SubjectDN = entity.SubjectDN,
            Issuer = entity.Issuer,
            NotBefore = entity.NotBefore,
            NotAfter = entity.NotAfter,
            Thumbprints = entity.Thumbprints,
            IsCA = entity.IsCA,
            ValidFrom = entity.ValidFrom,
            ValidTo = entity.ValidTo,
            Revoked = entity.Revoked,
            RevocationReason = entity.RevocationReason ?? string.Empty,
            RevocationDate = entity.RevocationDate,
            SigningProfileId = entity.SigningProfileId ?? Guid.Empty,
        };
    }

    public async Task<List<CertificateInfoModel>> GetAllCertificatesAsync()
    {
        var entities = await _dbContext.Certificates.AsNoTracking().ToListAsync();

        return entities.Select(c => new CertificateInfoModel
        {
            CertificateId = c.CertificateId,
            SerialNumber = c.SerialNumber,
            SubjectDN = c.SubjectDN,
            Issuer = c.Issuer,
            NotBefore = c.NotBefore,
            NotAfter = c.NotAfter,
            Thumbprints = c.Thumbprints,
            IsCA = c.IsCA,
            ValidFrom = c.ValidFrom,
            ValidTo = c.ValidTo,
            Revoked = c.Revoked,
            RevocationReason = c.RevocationReason ?? string.Empty,
            RevocationDate = c.RevocationDate,
            SigningProfileId = c.SigningProfileId ?? Guid.Empty,
            SubjectAlternativeNames = string.IsNullOrWhiteSpace(c.SubjectAlternativeNamesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.SubjectAlternativeNamesJson)!,

            KeyUsages = string.IsNullOrWhiteSpace(c.KeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.KeyUsagesJson)!,

            ExtendedKeyUsages = string.IsNullOrWhiteSpace(c.ExtendedKeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.ExtendedKeyUsagesJson)!,

        }).ToList();
    }

    public async Task RevokeCertificateAsync(string serialNumber, string reason)
    {
        var entity = await _dbContext.Certificates.FirstOrDefaultAsync(c => c.SerialNumber == serialNumber);

        if (entity == null)
            throw new InvalidOperationException("Certificate not found.");

        entity.Revoked = true;
        entity.RevocationReason = reason;

        await _dbContext.SaveChangesAsync();
    }

    public async Task<CertificateInfoModel?> GetCertificateByIdAsync(Guid id)
    {
        var entity = await _dbContext.Certificates.FindAsync(id);
        if (entity == null)
            return null;

        return new CertificateInfoModel
        {
            Pem = entity.Pem,
            CertificateId = entity.CertificateId,
            SerialNumber = entity.SerialNumber,
            SubjectDN = entity.SubjectDN,
            Issuer = entity.Issuer,
            NotBefore = entity.NotBefore,
            NotAfter = entity.NotAfter,
            Thumbprints = entity.Thumbprints,
            IsCA = entity.IsCA,
            ValidFrom = entity.ValidFrom,
            ValidTo = entity.ValidTo,
            Revoked = entity.Revoked,
            RevocationReason = entity.RevocationReason ?? string.Empty,
            RevocationDate = entity.RevocationDate,
            SigningProfileId = entity.SigningProfileId ?? Guid.Empty,
        };
    }
}
