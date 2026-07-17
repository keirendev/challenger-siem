using Microsoft.Extensions.Configuration;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Configuration;

public static class StartupConfigurationValidator
{
    private static readonly string[] RequiredKeys =
    {
        "ConnectionStrings:SiemDatabase",
        "Auth:EnrollmentToken"
    };

    public static void ValidateRequiredConfiguration(IConfiguration configuration)
    {
        var missing = RequiredKeys
            .Where(key => string.IsNullOrWhiteSpace(ReadValue(configuration, key)))
            .ToArray();

        if (missing.Length == 0)
        {
            ValidateIngestionBounds(configuration);
            return;
        }

        throw new InvalidOperationException(
            "Missing required Challenger SIEM configuration: "
            + string.Join(", ", missing)
            + ". Set these values with environment variables or an ignored local settings file. Secret values are intentionally not shown.");
    }

    private static void ValidateIngestionBounds(IConfiguration configuration)
    {
        var configured = configuration["Ingestion:MaxEventsPerBatch"];
        if (string.IsNullOrWhiteSpace(configured))
        {
            return;
        }

        if (!int.TryParse(configured, out var value) || value is < 1 or > ContractLimits.MaxIngestEventsPerBatch)
        {
            throw new InvalidOperationException(
                $"Invalid Challenger SIEM configuration: Ingestion:MaxEventsPerBatch must be between 1 and {ContractLimits.MaxIngestEventsPerBatch}. The configured value is intentionally not shown.");
        }
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
