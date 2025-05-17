using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ModularCA.Shared.Models.Crl;

namespace ModularCA.Core.Interfaces
{
    public interface ICrlConfigurationService
    {
        Task<CrlConfigurationDto> GetAsync();
        Task UpdateAsync(UpdateCrlConfigurationRequest request);
    }

}
