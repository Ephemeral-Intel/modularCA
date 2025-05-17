using Org.BouncyCastle.Pkcs;
using ModularCA.Core.Models;
using ModularCA.Shared.Models.Issuance;

namespace ModularCA.Core.Interfaces
{
    public interface ICertificateIssuanceService
    {
        Task<string> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter, bool includeRoot);
    }


}
