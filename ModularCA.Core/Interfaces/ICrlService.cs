using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModularCA.Core.Interfaces
{
    public interface ICrlService
    {
        /// <summary>
        /// Generates a new CRL for the specified CA certificate.
        /// </summary>
        /// <param name="caCertificateId">The CA certificate's unique identifier.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>PEM-encoded CRL string.</returns>
        Task<string> GenerateCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the latest CRL for the specified CA certificate.
        /// </summary>
        /// <param name="caCertificateId">The CA certificate's unique identifier.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>PEM-encoded CRL string.</returns>
        Task<string?> GetLatestCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Exports the CRL to a file.
        /// </summary>
        /// <param name="caCertificateId">The CA certificate's unique identifier.</param>
        /// <param name="outputPath">The file path to export the CRL.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        //Task ExportCrlToFileAsync(Guid caCertificateId, string outputPath, CancellationToken cancellationToken = default);
    }
}
