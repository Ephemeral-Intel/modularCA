using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Crl
{
    public class CrlConfigurationDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public TimeSpan Interval { get; set; }
        public TimeSpan OverlapPeriod { get; set; }
        public bool EnableDelta { get; set; }
        public TimeSpan? DeltaInterval { get; set; }
        public DateTime LastGenerated { get; set; }
    }

}
