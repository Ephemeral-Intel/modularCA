using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Functions.Services
{
    public class CertificateRevocationService : ICertificateRevocationService
    {
        private readonly ModularCADbContext _db;
        private readonly IKeystoreCertificates _keystore;
        private readonly ICertificateStore _certStore;

        public CertificateRevocationService(ModularCADbContext db, IKeystoreCertificates keystore, ICertificateStore certStore)
        {
            _db = db;
            _keystore = keystore;
            _certStore = certStore;
        }

        public async Task RevokeCertificateAsync(Guid? certificateId, string? certificateSerialNumber, string reason)
        {
            if(certificateId.HasValue)
            {
                var cert = await _certStore.GetCertificateByIdAsync(certificateId.Value);
                if (cert == null)
                {
                    throw new Exception("Certificate not found.");
                }
                cert.Revoked = true;
                cert.RevocationReason = reason;
                cert.RevocationDate = System.DateTime.UtcNow;
                var certEntity = _db.Certificates
                    .Where(a => a.CertificateId == certificateId)
                    .FirstOrDefault();
                if (certEntity == null)
                {
                    throw new Exception("Certificate not found.");
                }
                certEntity.Revoked = cert.Revoked;
                certEntity.RevocationReason = cert.RevocationReason;
                certEntity.RevocationDate = cert.RevocationDate;
                await _db.SaveChangesAsync();
            }

            else
            {
                var cert = await _certStore.GetCertificateBySerialNumberAsync(certificateSerialNumber);
                if (cert == null)
                {
                    throw new Exception("Certificate not found.");
                }
                cert.Revoked = true;
                cert.RevocationReason = reason;
                cert.RevocationDate = System.DateTime.UtcNow;
                var certEntity = _db.Certificates
                    .Where(a => a.SerialNumber == certificateSerialNumber)
                    .FirstOrDefault();
                if (certEntity == null)
                {
                    throw new Exception("Certificate not found.");
                }
                certEntity.Revoked = cert.Revoked;
                certEntity.RevocationReason = cert.RevocationReason;
                certEntity.RevocationDate = cert.RevocationDate;
                await _db.SaveChangesAsync();
            }
            
        }

        public async Task ReissueCertificateAsync(Guid certificateId, DateTime notBefore, DateTime notAfter, bool includeRoot)
        {
            var cert = await _db.Certificates.FindAsync(certificateId);
            if (cert == null)
            {
                throw new Exception("Certificate not found.");
            }
            var csr = _db.CertificateRequests
                .Where(a => a.IssuedCertificateId == cert.CertificateId)
                .FirstOrDefault();
            // Logic to reissue the certificate
            // This might involve creating a new CSR and signing it with the CA's private key
            // For now, just updating the existing certificate's validity dates
            cert.ValidFrom = notBefore;
            cert.ValidTo = notAfter;
            await _db.SaveChangesAsync();
        }
    }
}
