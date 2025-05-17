using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Database;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ModularCA.Functions.Services;

namespace ModularCA.Scheduler;

public class SchedulerService(IServiceProvider serviceProvider, ILogger<SchedulerService> logger) : BackgroundService
{
    private readonly IServiceProvider _serviceProvider = serviceProvider;
    private readonly ILogger<SchedulerService> _logger = logger;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SchedulerService started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

                // --- CRL Jobs ---
                var crlTasks = await dbContext.Schedules
                    .Where(s => s.Enabled && s.Type == "CRL")
                    .ToListAsync(stoppingToken);

                foreach (var task in crlTasks)
                {
                    var options = JsonSerializer.Deserialize<CrlScheduleOptions>(task.PayloadJson);
                    var caName = options?.CaName;

                    if (!string.IsNullOrWhiteSpace(caName))
                    {
                        var crlService = scope.ServiceProvider.GetRequiredService<CrlService>();
                        var crlBytes = await crlService.GenerateAndStoreCrlAsync(options.IsDelta);

                        var outputPath = Path.Combine("crl-output", $"{caName}{(options.IsDelta ? "-delta" : "")}.crl");
                        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
                        await File.WriteAllBytesAsync(outputPath, crlBytes, stoppingToken);

                        _logger.LogInformation("CRL written for {CaName} to {Path}", caName, outputPath);
                    }
                }

                // --- LDAP Jobs ---
                var ldapTasks = await dbContext.Schedules
                    .Where(s => s.Enabled && s.Type == "LDAP")
                    .ToListAsync(stoppingToken);

                foreach (var task in ldapTasks)
                {
                    var options = JsonSerializer.Deserialize<JobRunners.LdapScheduleOptions>(task.PayloadJson);
                    if (options == null) continue;

                    var ldapJob = scope.ServiceProvider.GetRequiredService<JobRunners.LdapPublisherJob>();
                    await ldapJob.RunAsync(options, stoppingToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error executing scheduled tasks");
            }

            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}

public class CrlScheduleOptions
{
    public string CaName { get; set; } = string.Empty;
    public bool IsDelta { get; set; }
}

public class LdapScheduleOptions
{
    public string CaName { get; set; } = string.Empty;
    public string LdapHost { get; set; } = string.Empty;
    public int LdapPort { get; set; } = 389;
    public string BaseDn { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool PublishCRL { get; set; }
    public bool PublishDelta { get; set; }
    public bool PublishCACert { get; set; }
}
