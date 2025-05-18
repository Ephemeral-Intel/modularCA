using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Scheduler
{
    public class CrlExportScheduleOptions
    {

        public Guid TaskId { get; set; }
        public Guid CaCertificateId { get; set; }
        public Guid CrlId { get; set; } = Guid.Empty;

    }
}
