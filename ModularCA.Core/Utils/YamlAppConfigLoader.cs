using System.IO;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Core.Utils
{
    public static class YamlAppConfigLoader
    {
        public static T Load<T>(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException($"YAML config not found: {path}");

            var yaml = File.ReadAllText(path);

            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(PascalCaseNamingConvention.Instance)
                .Build();

            return deserializer.Deserialize<T>(yaml);
        }
    }
}