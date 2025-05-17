using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Issuance
{
    public class IssueCertificateRequest
    {
        public Guid CsrId { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public bool IncludeRoot { get; set; } = false;
    }
}
