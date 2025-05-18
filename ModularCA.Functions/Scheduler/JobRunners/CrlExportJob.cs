using ModularCA.Core.Interfaces;
using ModularCA.Core.Utils;
using ModularCA.Database;
using ModularCA.Functions.Services;
using ModularCA.Shared.Entities;
using Org.BouncyCastle.X509;
using System.Text.Json;
using ModularCA.Shared.Models.Scheduler;
using NCrontab;
using Org.BouncyCastle.Asn1.X509;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Ocsp;

namespace ModularCA.Functions.Scheduler.JobRunners
{

    public class CrlExportJob : ISchedulerJobService
    {
        private readonly ICrlService _crlService;
        private readonly ModularCADbContext _db;

        public CrlExportJob(ICrlService crlService, ModularCADbContext db)
        {
            _crlService = crlService;
            _db = db;
        }

        public async Task RunAsync(object task, string cronExpression, CancellationToken cancellationToken)
        {
            try
            {
                if (task is not CrlExportScheduleOptions CrlTask)
                {
                    throw new ArgumentException("Invalid task type");
                }
                var caCertificate = _db.Certificates
                    .Where(c => c.CertificateId == CrlTask.CaCertificateId)
                    .FirstOrDefault();
                
                if (caCertificate == null)
                {
                    throw new Exception($"CA certificate with ID {CrlTask.CaCertificateId} not found.");
                }
                var crl = await _crlService.GetLatestCrlAsync(caCertificate.CertificateId, cancellationToken);
                
                if (string.IsNullOrEmpty(crl))
                {
                    Console.WriteLine($"No CRL found for CA certificate with ID {CrlTask.CaCertificateId}.");
                }

                if (await CheckNewCrlEntries(caCertificate, cancellationToken) == true)
                {
                    var newCrlPem = await _crlService.GenerateCrlAsync(caCertificate.CertificateId, cancellationToken);
                    var newCrlDer = CertificateUtil.ParseCrlFromPem(newCrlPem);
                    var parsedCron = CrontabSchedule.Parse(cronExpression);
                    var nextUpdate = parsedCron.GetNextOccurrence(DateTime.UtcNow);
                    var newCrlCert = new X509Crl(newCrlDer);

                    var dbCrl = await _db.Crls
                        .Where(c => c.TaskId == CrlTask.TaskId)
                        .FirstOrDefaultAsync();

                    if(dbCrl == null)
                        throw new Exception("Could not find associated CRL entry after CRL construction");

                    dbCrl.BaseCrlSerial = newCrlCert.GetExtensionValue(X509Extensions.CrlNumber)?.ToString();
                    dbCrl.PemData = newCrlPem;
                    dbCrl.RawData = newCrlDer;
                    dbCrl.NextUpdate = nextUpdate;
                    dbCrl.GeneratedAt = System.DateTime.UtcNow;
                    dbCrl.ThisUpdate = System.DateTime.UtcNow;
                    _db.Crls.Update(dbCrl);
                    await _db.SaveChangesAsync(cancellationToken);
                }

                else
                {
                    Console.WriteLine($"No new CRL entries found for CA certificate {CrlTask.CaCertificateId}.");
                    var now = DateTime.UtcNow;
                    var ParsedUpdate = CrontabSchedule.Parse(cronExpression);
                    var nextUpdate = ParsedUpdate.GetNextOccurrence(now);
                    var UpdateCrlJobSchedule = _db.CrlConfigurations
                    .Where(j => j.TaskId == CrlTask.TaskId)
                    .FirstOrDefault();

                    if (UpdateCrlJobSchedule == null)
                        throw new Exception("Could not find associated CRL scheduled job for next run time update");

                    UpdateCrlJobSchedule.NextUpdateUtc = nextUpdate;
                    _db.CrlConfigurations.Update(UpdateCrlJobSchedule);

                    var updateCrl = await _db.Crls
                        .Where(c => c.TaskId == CrlTask.TaskId)
                        .FirstOrDefaultAsync(cancellationToken);
                    updateCrl.NextUpdate = nextUpdate;
                    _db.Crls.Update(updateCrl);

                    await _db.SaveChangesAsync(cancellationToken);
                }
              
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error exporting CRL: {ex.Message}");
            }

            // Optionally, log or handle the result
        }

        private async Task<bool> CheckNewCrlEntries(CertificateEntity caCertificate, CancellationToken cancellationToken = default)
        {
            // Get the CA certificate


            if (caCertificate == null)
                return false;

            // Get the latest CRL for this CA
            var latestCrl = await _db.Crls
                .Where(c => c.IssuerName == caCertificate.SubjectDN)
                .OrderByDescending(c => c.CrlNumber)
                .FirstOrDefaultAsync(cancellationToken);

            // Get all revoked certs for this CA
            var revokedCerts = await _db.Certificates
                .Where(c => c.Revoked && c.Issuer == caCertificate.SubjectDN)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            if (latestCrl == null)
            {
                // No CRL exists yet, so all revoked certs are new
                return revokedCerts.Any();
            }

            // If any revoked cert has a revocation date after the last CRL generation, it's new
            var newRevoked = revokedCerts.Any(cert =>
                cert.RevocationDate != null && cert.RevocationDate > latestCrl.GeneratedAt);

            return newRevoked;
        }
    }
}
