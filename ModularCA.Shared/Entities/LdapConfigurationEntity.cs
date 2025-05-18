using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("LdapConfigurations")]
public class LdapConfigurationEntity
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public string? Name { get; set; } = string.Empty;

    public bool Enabled { get; set; } = false;
    public string? Description { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 389;
    public bool UseSsl { get; set; } = false;   
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string BaseDn { get; set; } = string.Empty;
    public string CaName { get; set; } = string.Empty;
    public bool PublishCACert { get; set; } = false;
    public bool PublishCRL { get; set; } = false;
    public string UpdateInterval { get; set; } = string.Empty;
    public DateTime LastUpdatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime NextUpdateUtc { get; set; } = DateTime.UtcNow.AddHours(1);
    
}
