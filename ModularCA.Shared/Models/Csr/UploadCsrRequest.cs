using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Csr
{
        public class UploadCsrRequest
    {
        public string Pem { get; set; } = string.Empty;
        public Guid CertificateProfileId { get; set; }
        public Guid SigningProfileId { get; set; }
    }
}
