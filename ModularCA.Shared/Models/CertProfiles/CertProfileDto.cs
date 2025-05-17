namespace ModularCA.Shared.Models.CertProfiles;

public class CertProfileDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsCaProfile {  get; set; }
    public bool IncludeRootInChain { get; set; } 
    public string KeyUsage { get; set; } = string.Empty;
    public string ExtendedKeyUsage { get; set; } = string.Empty;
    public string ValidityPeriod { get; set; } = string.Empty;
}
