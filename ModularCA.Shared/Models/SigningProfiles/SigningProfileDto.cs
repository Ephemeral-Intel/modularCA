namespace ModularCA.Shared.Models.SigningProfiles;
public class SigningProfileDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SignatureAlgorithm { get; set; } = string.Empty;

    public string KeyAlgorithm {  get; set; } = string.Empty;
    public string KeySize {  get; set; } = string.Empty;
    public string ValidityPeriodMin { get; set; } = string.Empty;
    public string ValidityPeriodMax { get; set; } = string.Empty;
    public bool IsDefault { get; set; }
}
