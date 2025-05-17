using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Revocation
{
    public class RevokeCertificateRequestByCertId
    {
        public Guid CertificateId { get; set; }
        public string Reason { get; set; } = string.Empty;
    }

    public class RevokeCertificateRequestByCertSerial
    {
        public string SerialNumber{ get; set; }
        public string Reason { get; set; } = string.Empty;
    }
}
