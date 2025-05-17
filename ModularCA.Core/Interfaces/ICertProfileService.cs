using ModularCA.Shared.Models.CertProfiles;

namespace ModularCA.Core.Interfaces
{
    public interface ICertProfileService
    {
        Task<List<CertProfileDto>> GetAllAsync();
        Task<CertProfileDto> CreateAsync(CreateCertProfileRequest request);
        Task UpdateAsync(int id, UpdateCertProfileRequest request);
        Task DeleteAsync(int id);
        Task<CertProfileDto?> GetByIdAsync(Guid id);

    }
}