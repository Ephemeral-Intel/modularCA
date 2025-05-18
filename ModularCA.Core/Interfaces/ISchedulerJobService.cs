using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Core.Interfaces
{
    public interface ISchedulerJobService
    {
        Task RunAsync(object task, string cronExpression, CancellationToken cancellationToken);
    }
}
