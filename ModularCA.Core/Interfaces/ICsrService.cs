using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ModularCA.Shared.Models.Csr;

namespace ModularCA.Core.Interfaces
{
    public interface ICsrService
    {
        Task<string> GenerateCsrAsync(CreateCsrRequest request);

        Task<string> UploadCsrAsync(string pem, Guid certProfileId, Guid signingProfileId);
    }

}
