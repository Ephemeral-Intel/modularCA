using ModularCA.API.Models;
using ModularCA.Core.Config;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.API.Startup;

public static class YamlConfigLoader
{
    public static Config Load(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"YAML config file not found: {path}");

        var yaml = File.ReadAllText(path);

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        return deserializer.Deserialize<Config>(yaml);
    }
}