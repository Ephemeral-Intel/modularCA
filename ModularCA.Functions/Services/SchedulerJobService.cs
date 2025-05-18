using ModularCA.Functions.Scheduler.JobRunners;
using ModularCA.Scheduler.JobRunners;
using ModularCA.Core.Interfaces;
using ModularCA.Shared.Models.Scheduler;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Functions.Services
{
    public class SchedulerJobService : IEnumerable<ISchedulerJobService>
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly Dictionary<string, (Type jobType, Type optionsType)> _jobMap = new()
        {
            { "LDAP", (typeof(LdapPublisherJob), typeof(LdapScheduleOptions)) },
            { "CRL_EXPORT", (typeof(CrlExportJob), typeof(CrlExportScheduleOptions)) },
            // Add more job types here as you implement them
        };

        public SchedulerJobService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public ISchedulerJobService? Resolve(string type)
        {
            if (_jobMap.TryGetValue(type, out var tuple))
                return _serviceProvider.GetService(tuple.jobType) as ISchedulerJobService;
            return null;
        }

        public Type? GetOptionsType(string type)
        {
            return _jobMap.TryGetValue(type, out var tuple) ? tuple.optionsType : null;
        }

        public IEnumerator<ISchedulerJobService> GetEnumerator()
        {
            foreach (var entry in _jobMap.Values)
            {
                var job = _serviceProvider.GetService(entry.jobType) as ISchedulerJobService;
                if (job != null)
                    yield return job;
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
