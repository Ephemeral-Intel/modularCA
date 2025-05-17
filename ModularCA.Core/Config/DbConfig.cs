﻿namespace ModularCA.Core.Config
{
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
}
