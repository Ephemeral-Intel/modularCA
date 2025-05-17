using System.Text;
using YamlDotNet.RepresentationModel;

namespace ModularCA.Keystore.Config
{
    public static class KeystoreYamlLoader
    {
        public static string LoadSecondaryPassphrase(string yamlPath, string keystoreName)
        {
            if (!File.Exists(yamlPath))
                throw new FileNotFoundException($"YAML file not found: {yamlPath}");

            using var reader = new StreamReader(yamlPath, Encoding.UTF8);

            var yaml = new YamlStream();
            yaml.Load(reader);

            if (yaml.Documents.Count == 0)
                throw new InvalidDataException("YAML file is empty or malformed");

            var root = (YamlMappingNode)yaml.Documents[0].RootNode;

            var key = Path.GetFileName(keystoreName);
            foreach (var entry in root.Children)
            {
                var currentKey = ((YamlScalarNode)entry.Key).Value;
                if (currentKey == key)
                {
                    return ((YamlScalarNode)entry.Value).Value ?? "";
                }
            }

            throw new KeyNotFoundException($"Secondary passphrase for '{key}' not found in {yamlPath}");
        }
    }
}
