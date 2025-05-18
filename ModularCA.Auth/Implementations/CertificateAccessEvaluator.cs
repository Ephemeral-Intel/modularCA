using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Auth.Implementations
{
    public class CertificateAccessEvaluator : ICertificateAccessEvaluator
    {
        private readonly ModularCADbContext _db;

        public CertificateAccessEvaluator(ModularCADbContext db)
        {
            _db = db;
        }

        public bool CanViewCertificate(Guid userId, Guid certificateId)
        {
            var cert = _db.Certificates
                .Include(c => c.CertificateAuthority)
                .FirstOrDefault(c => c.CertificateId == certificateId);
            if (cert == null) return false;

            // 1. SuperAdmin or SystemAdmin has full access
            if (_db.UserRoles.Any(r =>
                    r.UserId == userId &&
                    (r.Role == RoleType.SuperAdmin || r.Role == RoleType.SystemAdmin)))
                return true;

            // 2. CaAdmin, CaViewer, CaAuditor have scoped access
            if (cert.CertificateAuthority != null)
            {
                var caId = cert.CertificateAuthority.Id;
                if (_db.UserRoles.Any(r =>
                    r.UserId == userId &&
                    r.CertificateAuthorityId == caId &&
                    (r.Role == RoleType.CaAdmin || r.Role == RoleType.CaViewer || r.Role == RoleType.CaAuditor)))
                    return true;
            }

            // 3. Explicit ACL check
            return _db.CertificateAccessLists.Any(a =>
                a.UserId == userId &&
                a.CertificateId == certificateId &&
                a.AccessLevel >= CertificateAccessLevel.View);
        }

        public bool CanManageCertificate(Guid userId, Guid certificateId)
        {
            // Same as above but with Manage-level checks
            var cert = _db.Certificates
                .Include(c => c.CertificateAuthority)
                .FirstOrDefault(c => c.CertificateId == certificateId);
            if (cert == null) return false;

            if (_db.UserRoles.Any(r =>
                    r.UserId == userId &&
                    (r.Role == RoleType.SuperAdmin || r.Role == RoleType.SystemAdmin)))
                return true;

            if (cert.CertificateAuthority != null)
            {
                var caId = cert.CertificateAuthority.Id;
                if (_db.UserRoles.Any(r =>
                    r.UserId == userId &&
                    r.CertificateAuthorityId == caId &&
                    r.Role == RoleType.CaAdmin))
                    return true;
            }

            return _db.CertificateAccessLists.Any(a =>
                a.UserId == userId &&
                a.CertificateId == certificateId &&
                a.AccessLevel == CertificateAccessLevel.Manage);
        }
    }

}
