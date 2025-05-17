using Org.BouncyCastle.X509;
using ModularCA.Core.Utils;
namespace ModularCA.Core.Interfaces;

public interface ITrustStoreProvider
{
    IReadOnlyList<X509Certificate> GetTrustedCertificates();
    void LoadFromFile(string path);
}

public class InMemoryTrustStore : ITrustStoreProvider
{
    private readonly List<X509Certificate> _trustedCerts = new();

    public IReadOnlyList<X509Certificate> GetTrustedCertificates() => _trustedCerts.AsReadOnly();

    public void LoadFromFile(string path)
    {
        _trustedCerts.Clear();
        var loaded = TrustStoreLoader.LoadTrustStore(path);
        _trustedCerts.AddRange(loaded);
    }
}
