using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Enums
{
    public enum RoleType
    {
        SuperAdmin = 0,
        SystemAdmin = 1,
        CaAdmin = 2,
        CaViewer = 3,
        CaAuditor = 4,
        Auditor = 5,
        User = 6,
        Signer = 7
    }
}
