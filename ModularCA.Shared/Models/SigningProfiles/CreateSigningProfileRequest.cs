using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Shared.Models.SigningProfiles
{
    public class CreateSigningProfileRequest
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string SignatureAlgorithm { get; set; } = string.Empty;
        public string ValidityPeriodMin { get; set; } = "P47D";
        public string ValidityPeriodMax { get; set; } = "P2Y";
        public bool IsDefault { get; set; }
    }
}