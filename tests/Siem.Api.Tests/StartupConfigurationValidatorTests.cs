using Challenger.Siem.Api.Configuration;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class StartupConfigurationValidatorTests
{
    [Fact]
    public void ValidateRequiredConfigurationRejectsMissingAuthValuesWithoutPrintingSecrets()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:SiemDatabase"] = "Host=localhost;Database=challenger_siem;Username=siem;Password=super-secret-password",
                ["Auth:EnrollmentToken"] = "",
                ["Auth:ReviewToken"] = null
            })
            .Build();

        var exception = Assert.Throws<InvalidOperationException>(
            () => StartupConfigurationValidator.ValidateRequiredConfiguration(configuration));

        Assert.Contains("Auth:EnrollmentToken", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Auth:ReviewToken", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-password", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateRequiredConfigurationAcceptsRequiredValues()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:SiemDatabase"] = "Host=localhost;Database=challenger_siem;Username=siem;Password=redacted",
                ["Auth:EnrollmentToken"] = "enrollment-token",
                ["Auth:ReviewToken"] = "review-token"
            })
            .Build();

        StartupConfigurationValidator.ValidateRequiredConfiguration(configuration);
    }
}
