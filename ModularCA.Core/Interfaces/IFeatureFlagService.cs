namespace ModularCA.Core.Interfaces
{
    public interface IFeatureFlagService
    {
        bool IsEnabled(string flagName);
        string? GetValue(string flagName);
        (bool Enabled, string? Value)? Get(string flagName);
    }
}
