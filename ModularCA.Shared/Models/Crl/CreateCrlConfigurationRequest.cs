using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Crl
{
    public class CreateCrlConfigurationRequest
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string UpdateInterval { get; set; } = string.Empty;
        public TimeSpan OverlapPeriod { get; set; }
        public bool IsDelta { get; set; }
        public string DeltaInterval { get; set; } = string.Empty;
        public Guid CaCertificateId { get; set; }
    }
}
