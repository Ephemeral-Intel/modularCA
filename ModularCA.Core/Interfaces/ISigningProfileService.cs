using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Models.SigningProfiles;

namespace ModularCA.Core.Interfaces;
public interface ISigningProfileService
{
    Task<List<SigningProfileDto>> GetAllAsync();
    Task<SigningProfileDto> CreateAsync(CreateSigningProfileRequest request);
    Task UpdateAsync(Guid id, UpdateSigningProfileRequest request);
    Task DeleteAsync(Guid id);
    Task<string> GetValidityMinimum(Guid id);
    Task<string> GetValidityMaximum(Guid id);
    Task<SigningProfileDto?> GetByIdAsync(Guid id);
}
