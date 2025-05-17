namespace ModularCA.Core.Config
{
    public class CaConfig
    {
        public KeystorePaths Keystore { get; set; } = new();
        public string SigningProfile { get; set; } = "default";
    }

    public class KeystorePaths
    {
        public string CertPath { get; set; } = "ca-cert.keystore";
        public string TrustPath { get; set; } = "ca-trust.keystore";
        public string Password { get; set; } = string.Empty;
    }
}
