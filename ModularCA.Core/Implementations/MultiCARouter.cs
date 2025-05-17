using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;

namespace ModularCA.Core.Implementations
{
    public class MultiCARouter(List<BouncyCastleCertificateAuthority> authorities, IKeystoreCertificates certStore) : ICertificateAuthority
    {
        private readonly List<BouncyCastleCertificateAuthority> _authorities = authorities;
        private readonly IKeystoreCertificates _certStore = certStore;

        public Task<byte[]> IssueCertificateAsync(CertificateRequestModel request)
        {
            // Pick first CA (or smarter matching)
            var ca = _authorities.FirstOrDefault();
            if (ca == null)
                throw new InvalidOperationException("No signing CA available");

            return ca.IssueCertificateAsync(request);
        }

        public Task<byte[]> IssueCertificateFromCsrAsync(byte[] csr, DateTime notBefore, DateTime notAfter, bool isCa)
        {
            var ca = _authorities.FirstOrDefault();
            if (ca == null)
                throw new InvalidOperationException("No signing CA available");

            return ca.IssueCertificateFromCsrAsync(csr, notBefore, notAfter, isCa);
        }

        public Task<bool> RevokeCertificateAsync(string serial, string reason) =>
            Task.FromResult(false); // stub for now

        public Task<CertificateInfoModel> GetCertificateInfoAsync(string serial) =>
            throw new NotImplementedException();
    }

}
