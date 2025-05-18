using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Functions.Services;
using ModularCA.Shared.Models.Scheduler;

namespace ModularCA.Functions.Services
{
    public class SchedulerService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<SchedulerService> _logger;
        private readonly TimeSpan _pollInterval = TimeSpan.FromSeconds(30);

        public SchedulerService(IServiceProvider serviceProvider, ILogger<SchedulerService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

         
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("SchedulerService started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using var scope = _serviceProvider.CreateScope();
                    var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
                    var jobDispatcher = scope.ServiceProvider.GetRequiredService<SchedulerJobService>();

                    // CRL Export Jobs
                    var crlJobs = db.CrlConfigurations.AsNoTracking().ToList();
                    foreach (var crlJob in crlJobs)
                    {
                        var jobService = jobDispatcher.Resolve("CRL_EXPORT");
                        var optionsType = jobDispatcher.GetOptionsType("CRL_EXPORT");
                        if (jobService != null && optionsType != null && 
                            (crlJob.NextUpdateUtc <= System.DateTime.UtcNow) && (crlJob.Enabled == true))
                        {
                            var options = Activator.CreateInstance(optionsType) as CrlExportScheduleOptions;
                            if (options != null)
                            {
                                options.CaCertificateId = crlJob.CaCertificateId;
                                options.TaskId = crlJob.TaskId;
                                await jobService.RunAsync(options, crlJob.UpdateInterval, stoppingToken);
                            }
                        }
                    }

                    // LDAP Publisher Jobs
/*                  I saw we comment this out for now until it gets implemented
                    var ldapJobs = db.LdapConfigurations.AsNoTracking().ToList();
                    foreach (var ldapJob in ldapJobs)
                    {
                        var jobService = jobDispatcher.Resolve("LDAP");
                        var optionsType = jobDispatcher.GetOptionsType("LDAP");
                        if (jobService != null && optionsType != null)
                        {
                            var options = Activator.CreateInstance(optionsType) as LdapScheduleOptions;
                            if (options != null)
                            {
                                options.TaskId = ldapJob.Id;
                                await jobService.RunAsync(options, ldapJob.UpdateInterval, stoppingToken);
                            }
                        }
                    }
*/
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "SchedulerService main loop error");
                }

                await Task.Delay(_pollInterval, stoppingToken);
            }

            _logger.LogInformation("SchedulerService stopped.");
        }

    }
}
