using System.DirectoryServices.Protocols;
using ModularCA.Shared.Models.Scheduler;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using Microsoft.EntityFrameworkCore;

namespace ModularCA.Scheduler.JobRunners;

public class LdapPublisherJob
{
    private readonly ModularCADbContext _dbContext;
    private readonly ILogger<LdapPublisherJob> _logger;

    public LdapPublisherJob(ModularCADbContext dbContext, ILogger<LdapPublisherJob> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    public async Task RunAsync(LdapScheduleOptions options,string cronExpression, CancellationToken cancellationToken)
    {
        try
        {
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(options.LdapHost, options.LdapPort));
            connection.AuthType = AuthType.Basic;
            connection.Credential = new NetworkCredential(options.Username, options.Password);
            connection.Bind();

            _logger.LogInformation("LDAP bind successful to {Host}:{Port}", options.LdapHost, options.LdapPort);

            var caName = options.CaName;

            if (options.PublishCACert)
            {
                var cert = await _dbContext.Certificates
                    .Where(c => c.SubjectDN == caName && !c.Revoked)
                    .OrderByDescending(c => c.ValidTo)
                    .Select(c => c.RawCertificate)
                    .FirstOrDefaultAsync(cancellationToken);

                if (cert != null)
                {
                    var request = new ModifyRequest(options.BaseDn, DirectoryAttributeOperation.Replace, "cACertificate", cert);
                    connection.SendRequest(request);
                    _logger.LogInformation("Published CA certificate to LDAP under {BaseDn}", options.BaseDn);
                }
            }

            if (options.PublishCRL)
            {
                var crl = await _dbContext.Crls
                    .Where(c => c.IssuerName == caName && !c.IsDelta)
                    .OrderByDescending(c => c.CrlNumber)
                    .Select(c => c.RawData)
                    .FirstOrDefaultAsync(cancellationToken);

                if (crl != null)
                {
                    var request = new ModifyRequest(options.BaseDn, DirectoryAttributeOperation.Replace, "certificateRevocationList", crl);
                    connection.SendRequest(request);
                    _logger.LogInformation("Published CRL to LDAP under {BaseDn}", options.BaseDn);
                }
            }

            if (options.PublishDelta)
            {
                var delta = await _dbContext.Crls
                    .Where(c => c.IssuerName == caName && c.IsDelta)
                    .OrderByDescending(c => c.CrlNumber)
                    .Select(c => c.RawData)
                    .FirstOrDefaultAsync(cancellationToken);

                if (delta != null)
                {
                    var request = new ModifyRequest(options.BaseDn, DirectoryAttributeOperation.Replace, "deltaRevocationList", delta);
                    connection.SendRequest(request);
                    _logger.LogInformation("Published delta CRL to LDAP under {BaseDn}", options.BaseDn);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LDAP publishing failed for {CaName}", options.CaName);
        }
    }
}
