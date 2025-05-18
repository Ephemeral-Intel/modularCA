using ModularCA.Core.Models;

namespace ModularCA.Core.Interfaces;

public interface ICertificateStore
{
    Task SaveCertificateAsync(byte[] certificateBytes, CertificateInfoModel info, byte[]? encryptedPrivateKey = null);
    Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber);
    Task<IEnumerable<CertificateInfoModel>> ListAsync();
    Task<List<CertificateInfoModel>> GetAllCertificatesAsync();
    Task<CertificateInfoModel?> GetCertificateByIdAsync(Guid id);
    Task<CertificateInfoModel?> GetCertificateBySerialNumberAsync(string serialNumber);

}
