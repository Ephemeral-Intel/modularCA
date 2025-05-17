using ModularCA.API.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.API.Startup;

public static class YamlDbLoader
{
    public static DbConfig Load(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"YAML config file not found: {path}");

        var yaml = File.ReadAllText(path);

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        return deserializer.Deserialize<DbConfig>(yaml);
    }
}