using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ModularCA.Core.Utils
{
    public class Iso8601ParserUtil()
    {
        public static TimeSpan ParseIso8601(string duration)
        {

            // Only supports: PnY, PnM, PnD, or combinations like P1Y6M10D
            int years = 0, months = 0, days = 0;

            if (!duration.StartsWith("P"))
                throw new FormatException("Invalid duration format");

            duration = duration.Substring(1); // remove 'P'
            var matches = Regex.Matches(duration, @"(\d+)([YMD])");

            foreach (Match match in matches)
            {
                var value = int.Parse(match.Groups[1].Value);
                switch (match.Groups[2].Value)
                {
                    case "Y": years = value; break;
                    case "M": months = value; break;
                    case "D": days = value; break;
                }
            }

            var future = DateTime.UtcNow.AddYears(years).AddMonths(months).AddDays(days);
            return future - DateTime.UtcNow; // returns as a TimeSpan
        }
    }
}
