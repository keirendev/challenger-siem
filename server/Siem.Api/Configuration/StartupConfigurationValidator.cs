using Microsoft.Extensions.Configuration;

namespace Challenger.Siem.Api.Configuration;

public static class StartupConfigurationValidator
{
    private static readonly string[] RequiredKeys =
    {
        "ConnectionStrings:SiemDatabase",
        "Auth:EnrollmentToken",
        "Auth:ReviewToken"
    };

    public static void ValidateRequiredConfiguration(IConfiguration configuration)
    {
        var missing = RequiredKeys
            .Where(key => string.IsNullOrWhiteSpace(ReadValue(configuration, key)))
            .ToArray();

        if (missing.Length == 0)
        {
            return;
        }

        throw new InvalidOperationException(
            "Missing required Challenger SIEM configuration: "
            + string.Join(", ", missing)
            + ". Set these values with environment variables or an ignored local settings file. Secret values are intentionally not shown.");
    }

    private static string? ReadValue(IConfiguration configuration, string key)
    {
        const string connectionPrefix = "ConnectionStrings:";
        if (key.StartsWith(connectionPrefix, StringComparison.Ordinal))
        {
            return configuration.GetConnectionString(key[connectionPrefix.Length..]);
        }

        return configuration[key];
    }
}
