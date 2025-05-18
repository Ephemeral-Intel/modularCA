using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Auth.Interfaces
{
    public interface ICertificateAccessEvaluator
    {
        bool CanViewCertificate(Guid userId, Guid certificateId);
        bool CanManageCertificate(Guid userId, Guid certificateId);
    }
}
