using System.Threading.Tasks;

namespace ModularCA.Core.Interfaces;

public interface IRawCertificateStore : ICertificateStore
{
    Task<byte[]?> GetRawCertificateAsync(string serialNumber);
}
