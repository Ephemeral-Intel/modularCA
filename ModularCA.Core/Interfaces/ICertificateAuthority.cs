using ModularCA.Core.Models;

namespace ModularCA.Core.Interfaces;

public interface ICertificateAuthority
{
    Task<byte[]> IssueCertificateAsync(CertificateRequestModel request);
    Task<byte[]> IssueCertificateFromCsrAsync(byte[] csrBytes, DateTime notBefore, DateTime notAfter, bool isCA = false);
    Task<bool> RevokeCertificateAsync(string serialNumber, string reason);
    Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber);
}
