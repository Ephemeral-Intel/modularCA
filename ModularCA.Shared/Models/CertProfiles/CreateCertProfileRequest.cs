namespace ModularCA.Shared.Models.CertProfiles;

public class CreateCertProfileRequest
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsCaProfile {  get; set; }
    public bool IncludeRootInChain { get; set; }

    // Add your specific fields for the profile:
    public string KeyUsage { get; set; } = string.Empty;
    public string ExtendedKeyUsage { get; set; } = string.Empty;
    public string ValidityPeriod { get; set; } = string.Empty; // e.g. "P1Y" 
}
