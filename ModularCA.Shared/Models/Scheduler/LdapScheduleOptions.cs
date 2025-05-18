using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Scheduler
{
    public class LdapScheduleOptions
    {
        public string CaName { get; set; } = string.Empty;
        public string LdapHost { get; set; } = string.Empty;
        public int LdapPort { get; set; } = 389;
        public string BaseDn { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool PublishCRL { get; set; }
        public bool PublishDelta { get; set; }
        public bool PublishCACert { get; set; }
        
        public Guid TaskId { get; set; }
    }
}
