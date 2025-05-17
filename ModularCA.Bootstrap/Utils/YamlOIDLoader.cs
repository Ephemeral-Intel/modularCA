using System.IO;
using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Bootstrap.Utils
{
    public static class YamlOIDLoader
    {
        public static OIDSeedConfig Load(string path)
        {
            var yaml = File.ReadAllText(path);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(PascalCaseNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();

            return deserializer.Deserialize<OIDSeedConfig>(yaml);
        }

        public class OIDSeedConfig
        {
            public OID OID { get; set; } = new();
        }

        public class OID
        {
            public Dictionary<string, string>? StandardKeyUsage { get; set; } = new();
            public Dictionary<string, string>? ExtendedKeyUsage { get; set; } = new();
        }

/*        public class StandardKeyDict
        {
            public List<string>? StandardKeyUsage { get; set; }

        }
        public class ExtendedKeyDict
        {
            public List<string>? ExtendedKeyUsage { get; set; }

        }*/
    }
}
