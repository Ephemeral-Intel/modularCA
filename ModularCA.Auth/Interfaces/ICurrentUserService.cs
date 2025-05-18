using ModularCA.Shared.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Auth.Interfaces
{
    public interface ICurrentUserService
    {
        Guid? UserId { get; }
        UserEntity? User { get; }
        bool IsAuthenticated { get; }

        Task EnsureLoadedAsync(); // call before using User
    }

}
