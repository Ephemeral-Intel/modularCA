namespace ModularCA.Core.Config
{

    public class Config
    {
        public DbConfig DB { get; set; } = new();

        public JwtConfig JWT { get; set; } = new();
    }

    public class DbConfig
    {
        public DbInstance App { get; set; } = new();
        public DbInstance Audit { get; set; } = new();
    }

    public class DbInstance
    {
        public string Host { get; set; } = "localhost";
        public int Port { get; set; } = 3306;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Database { get; set; } = string.Empty;
    }

    public class JwtConfig
    {
        public string Secret { get; set; } = string.Empty;
        public int ExpirationMinutes { get; set; } = 60;
    }
}
