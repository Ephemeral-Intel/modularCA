using System.IO;
using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Bootstrap.Utils
{
    public static class YamlBootstrapLoader
    {
        public static BootstrapConfig Load(string path)
        {
            var yaml = File.ReadAllText(path);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(PascalCaseNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();

            return deserializer.Deserialize<BootstrapConfig>(yaml);
        }

        public class BootstrapConfig
        {
            public CaConfig CA { get; set; } = new();
            public SigningProfileConfig SigningProfile { get; set; } = new();
            public SqlConfig SqlApp { get; set; } = new();
            public SqlConfig SqlAudit { get; set; } = new();

        }

        public class CaConfig
        {
            public string Algorithm { get; set; } = "RSA";
            public int KeySize { get; set; } = 4096;
            public int ValidityYears { get; set; } = 10;
            public CaSubjectConfig Subject { get; set; } = new();
        }

        public class CaSubjectConfig
        {
            public string? CN { get; set; }
            public string? O { get; set; }
            public List<string>? OU { get; set; }
            public List<string>? DC { get; set; }
            public string? L { get; set; }
            public string? ST { get; set; }
            public string? C { get; set; }
        }

        public class SigningProfileConfig
        {
            public string Name { get; set; } = "default";
            public bool IsCa { get; set; } = true;
            public List<string>? KeyUsages { get; set; }
            public List<string>? ExtendedKeyUsages { get; set; }
        }

        public class SqlConfig
        {
            public string Host { get; set; } = "localhost";
            public int Port { get; set; } = 3306;
            public string Database { get; set; } = "placeholder";
            public string Username { get; set; } = "notroot";
            public string Password { get; set; } = string.Empty;
        }
    }
}
