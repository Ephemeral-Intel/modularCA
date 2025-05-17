using System.Text;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.KeystoreFormat;
using ModularCA.Keystore.Secure;

namespace ModularCA.Keystore;

public static class Unlocker
{
    public static void Run(string[] args)
    {
        var path = GetArg(args, "--keystore") ?? throw new ArgumentException("Missing --keystore");
        var yamlPath = GetArg(args, "--yaml") ?? "config/keystore.yaml";
        var outputPath = GetArg(args, "--output"); // optional
        var print = args.Contains("--print");
        var verify = args.Contains("--verify");

        Console.WriteLine($"🔐 Loading keystore: {path}");

        var keystore = KeystoreFileParser.Parse(path);
        var secondaryPass = KeystoreYamlLoader.LoadSecondaryPassphrase(yamlPath, Path.GetFileName(path));
        var mainPass = LoadMainPassphrase();

        var key = ScryptKeyDeriver.DeriveFileKey(mainPass, secondaryPass, keystore);

        foreach (var entry in keystore.Entries)
        {
            var decrypted = AesGcmDecryptor.Decrypt(entry.Nonce, entry.Ciphertext, entry.Tag, key);

            if (print || string.IsNullOrWhiteSpace(outputPath))
            {
                Console.WriteLine("📄 Decrypted Content:\n");
                Console.WriteLine(Encoding.UTF8.GetString(decrypted));
            }
            else
            {
                var outputName = outputPath ?? "decrypted-output.bin";
                var numberedPath = keystore.Entries.Count > 1
                    ? Path.Combine(Path.GetDirectoryName(outputName)!, $"{Path.GetFileNameWithoutExtension(outputName)}_{keystore.Entries.IndexOf(entry)}{Path.GetExtension(outputName)}")
                    : outputName;

                File.WriteAllBytes(numberedPath, decrypted);
                Console.WriteLine($"✅ Decrypted entry written to: {numberedPath}");
            }
        }
    }

    private static string? GetArg(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index < args.Length - 1 ? args[index + 1] : null;
    }

    private static string LoadMainPassphrase()
    {
        Console.Write("🔑 Enter main passphrase: ");
        return Console.ReadLine() ?? throw new Exception("Main passphrase is required");
    }
}
