using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Core.Interfaces
{
    public interface ICertificateRevocationService
    {
        Task RevokeCertificateAsync(Guid? certificateId, string? certificateSerialNumber, string reason);

        Task ReissueCertificateAsync(Guid certificateId, DateTime notBefore, DateTime notAfter, bool includeRoot);
    }
}
