using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Issuance
{

    public class ReissueCertificateRequestByCertId
    {
        public Guid CertificateId { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public bool IncludeRoot { get; set; }
    }
    public class ReissueCertificateRequestByCertSn
    {
        public string SerialNumber { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public bool IncludeRoot { get; set; }
    }

    public class ReissueCertificateRequestByCsrId
    {
        public Guid CsrId { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public bool IncludeRoot { get; set; }
    }
}
