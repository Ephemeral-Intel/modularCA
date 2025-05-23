﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.Crl
{
    public class UpdateCrlConfigurationRequest
    {
        public Guid TaskId { get; set; }
        public string Description { get; set; } = string.Empty;
        public string UpdateInterval { get; set; }
        public TimeSpan OverlapPeriod { get; set; }
        public bool IsDelta { get; set; }
        public string DeltaInterval { get; set; }
    }

}
