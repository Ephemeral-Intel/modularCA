using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Core.Models
{
    public class CertificateCsrRequestModel
    {
        public byte[] CsrBytes { get; set; } = [];
        public Guid SigningProfileId { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public bool IsCA { get; set; } = false;
    }
}
