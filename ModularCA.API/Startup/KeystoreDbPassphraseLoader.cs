using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.KeystoreFormat;
using ModularCA.Database;
using ModularCA.Keystore.Crypto;
using ModularCA.API.Startup;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;

namespace ModularCA.API.Startup
{
    public static class KeystoreDbPassphraseLoader
    {
        public static string RetrieveFromDatabase(string name)
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "config", "db.yaml");
            var config = YamlBootstrapLoader.Load(configPath);
            var appConnStr = $"Server={config.App.Host};Port={config.App.Port};Database={config.App.Database};Uid={config.App.Username};Pwd={config.App.Password};";
            var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseMySql(appConnStr,
                      ServerVersion.AutoDetect(appConnStr))  // Adjust MariaDB version
            .Options;

            using var db = new ModularCADbContext(options);

            var entry = db.Keystores.AsNoTracking().FirstOrDefault(k => k.Name == name)
                ?? throw new Exception($"❌ Keystore '{name}' not found in database.");

            var keystoreConfigPath = Path.Combine(AppContext.BaseDirectory, "config", "keystore.yaml");
            var secondaryPass = KeystoreYamlLoader.LoadSecondaryPassphrase(keystoreConfigPath, name);

            var file = new KeystoreFile
            {
                ScryptN = 32768, // These may need to be stored in DB later
                ScryptR = 8,
                ScryptP = 1,
                ScryptSalt = entry.Salt,
            };

            var kek = ScryptKeyDeriver.DeriveFileKey("ModularCA:PassWrap", secondaryPass, file);

            var nonce = entry.Passblob[..12];
            var ciphertext = entry.Passblob[12..^16];
            var tag = entry.Passblob[^16..];


            var decryptedBytes = AesGcmDecryptor.Decrypt(nonce, ciphertext, tag, kek);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
