using System.Text.Json;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V1;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class TelemetryTextSanitizerTests
{
    [Theory]
    [InlineData(
        "/usr/bin/tool password=\"synthetic-secret with spaces\" --mode scan",
        "/usr/bin/tool password=\"<redacted>\" --mode scan")]
    [InlineData(
        "env 'TOKEN=synthetic-token with spaces' /usr/bin/tool",
        "env 'TOKEN=<redacted>' /usr/bin/tool")]
    [InlineData(
        "config {\"password\": \"synthetic-json secret\", \"mode\":\"safe\"}",
        "config {\"password\": \"<redacted>\", \"mode\":\"safe\"}")]
    [InlineData(
        "config {'api_key': 'synthetic-api key', 'mode':'safe'}",
        "config {'api_key': '<redacted>', 'mode':'safe'}")]
    [InlineData(
        "env AWS_SECRET_ACCESS_KEY=\"synthetic aws secret with spaces\" /usr/bin/tool",
        "env AWS_SECRET_ACCESS_KEY=\"<redacted>\" /usr/bin/tool")]
    [InlineData(
        "env GITHUB_TOKEN=synthetic-github-token /usr/bin/tool",
        "env GITHUB_TOKEN=<redacted> /usr/bin/tool")]
    [InlineData(
        "env PGPASSWORD=synthetic-pg-password MYSQL_PWD=synthetic-mysql-password /usr/bin/tool",
        "env PGPASSWORD=<redacted> MYSQL_PWD=<redacted> /usr/bin/tool")]
    [InlineData(
        "env SSHPASS=synthetic-sshpass-value /usr/bin/tool",
        "env SSHPASS=<redacted> /usr/bin/tool")]
    public void RedactsQuotedAndJsonLikeAssignmentsWithoutLeavingFragments(string input, string expected)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        AssertSuccessfulRedaction(result, expected);
        Assert.DoesNotContain("synthetic-secret", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-token", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-json", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-api", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic aws", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-github", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-pg", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-mysql", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-sshpass", result.Value, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(
        "curl -H \"Authorization: Bearer synthetic-bearer-fragment\" https://example.invalid",
        "curl -H \"Authorization: <redacted>\" https://example.invalid")]
    [InlineData(
        "curl --header 'Authorization: Basic synthetic-basic-fragment==' https://example.invalid",
        "curl --header 'Authorization: <redacted>' https://example.invalid")]
    [InlineData(
        "curl --header Authorization: Basic synthetic-unquoted-fragment https://example.invalid",
        "curl --header Authorization: <redacted> https://example.invalid")]
    [InlineData(
        "curl -HAuthorization:Bearer synthetic-short-header-fragment https://example.invalid",
        "curl -HAuthorization:<redacted> https://example.invalid")]
    [InlineData(
        "curl --header='Cookie: session=synthetic-cookie-fragment; csrf=synthetic-csrf-fragment' https://example.invalid",
        "curl --header='Cookie: <redacted>' https://example.invalid")]
    [InlineData(
        "curl -H \"X-Api-Key: synthetic-api-key fragment with spaces\" https://example.invalid",
        "curl -H \"X-Api-Key: <redacted>\" https://example.invalid")]
    public void RedactsQuotedAndUnquotedCurlSensitiveHeadersBeforeAssignments(string input, string expected)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        AssertSuccessfulRedaction(result, expected);
        Assert.DoesNotContain("fragment", result.Value, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(
        "Cookie: session=synthetic-cookie-one; csrf=synthetic-cookie-two",
        "Cookie: <redacted>")]
    [InlineData(
        "retained X-Api-Key: synthetic-api-key value with spaces",
        "retained X-Api-Key: <redacted>")]
    [InlineData(
        "Authorization: Custom synthetic-custom-auth value with spaces",
        "Authorization: <redacted>")]
    public void RedactsCompleteGenericSensitiveHeaderValues(string input, string expected)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        AssertSuccessfulRedaction(result, expected);
        Assert.DoesNotContain("synthetic-cookie", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-api-key", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-custom-auth", result.Value, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(
        "curl -u synthetic-user:synthetic-curl-password https://example.invalid",
        "curl -u <redacted> https://example.invalid")]
    [InlineData(
        "curl --user=\"synthetic user:synthetic password with spaces\" https://example.invalid",
        "curl --user=\"<redacted>\" https://example.invalid")]
    [InlineData(
        "sshpass -p 'synthetic ssh password' ssh example.invalid",
        "sshpass -p '<redacted>' ssh example.invalid")]
    [InlineData(
        "sshpass -v -psynthetic-attached-password ssh example.invalid",
        "sshpass -v -p<redacted> ssh example.invalid")]
    [InlineData(
        "sshpass -e synthetic-env-value ssh example.invalid",
        "sshpass -e <redacted> ssh example.invalid")]
    [InlineData(
        "SSHPASS -psynthetic-uppercase-command ssh example.invalid",
        "SSHPASS -p<redacted> ssh example.invalid")]
    [InlineData(
        "mysql -psynthetic-db-password -h example.invalid",
        "mysql -p<redacted> -h example.invalid")]
    [InlineData(
        "MYSQL -psynthetic-uppercase-db-password -h example.invalid",
        "MYSQL -p<redacted> -h example.invalid")]
    [InlineData(
        "mysql -u synthetic-user -p\"synthetic db password\" -h example.invalid",
        "mysql -u synthetic-user -p\"<redacted>\" -h example.invalid")]
    [InlineData(
        "mysql --password 'synthetic long-option password' -h example.invalid",
        "mysql --password '<redacted>' -h example.invalid")]
    [InlineData(
        "/usr/bin/tool --secret-access-key synthetic-secret-access-value --mode scan",
        "/usr/bin/tool --secret-access-key <redacted> --mode scan")]
    public void RedactsCommonCommandSpecificCredentialArguments(string input, string expected)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        AssertSuccessfulRedaction(result, expected);
        Assert.DoesNotContain("synthetic-curl-password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic ssh password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-attached-password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-env-value", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-uppercase-command", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-db-password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-uppercase-db-password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic db password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic long-option password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-secret-access-value", result.Value, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(
        "/usr/bin/tool --authorization Bearer synthetic-option-bearer-fragment --mode scan",
        "/usr/bin/tool --authorization <redacted> --mode scan")]
    [InlineData(
        "/usr/bin/tool --AUTHORIZATION Basic synthetic-option-basic-fragment --mode scan",
        "/usr/bin/tool --AUTHORIZATION <redacted> --mode scan")]
    [InlineData(
        "/usr/bin/tool authorization=Bearer synthetic-assignment-fragment --mode scan",
        "/usr/bin/tool authorization=<redacted> --mode scan")]
    public void RedactsAuthorizationSchemesBeforeGenericOptionOrAssignmentPasses(string input, string expected)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        AssertSuccessfulRedaction(result, expected);
        Assert.DoesNotContain("fragment", result.Value, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(
        "fetch https://synthetic-user:synthetic-uri-password@example.invalid/path",
        "fetch https://<redacted>@example.invalid/path")]
    [InlineData(
        "fetch HTTPS://synthetic-user:synthetic%20encoded%20password@example.invalid/path",
        "fetch HTTPS://<redacted>@example.invalid/path")]
    [InlineData(
        "client dsn=postgres://synthetic-user:synthetic-dsn-password@example.invalid/db",
        "client dsn=<redacted>")]
    public void RedactsUriUserInfo(string input, string expected)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        AssertSuccessfulRedaction(result, expected);
        Assert.DoesNotContain("synthetic-user", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-uri-password", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic%20encoded", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-dsn-password", result.Value, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/usr/bin/printf 'password policy and token rotation are enabled'")]
    [InlineData("curl --user-agent \"Challenger basic client\" https://example.invalid/keys")]
    [InlineData("psql -p5432 --user synthetic-user --host example.invalid")]
    [InlineData("mysql -P3306 --protocol tcp --host example.invalid")]
    [InlineData("mysql -p")]
    [InlineData("MYSQL -p --host example.invalid")]
    [InlineData("echo AWS_SECRET_ACCESS_KEY rotation policy")]
    [InlineData("env SSHPASS_POLICY=disabled /usr/bin/tool")]
    [InlineData("curl -H \"X-Api-Key-Rotation: enabled\" https://example.invalid")]
    [InlineData("/usr/bin/tool --secret-access-key-file /etc/example.invalid/key")]
    [InlineData("authorization policy: custom authentication is enabled")]
    [InlineData("fetch https://example.invalid/path")]
    public void PreservesBenignCommandsThatContainNearbyWordsOrOptions(string input)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        Assert.Equal(input, result.Value);
        Assert.False(result.Redacted);
        Assert.False(result.Dropped);
        Assert.False(result.Truncated);
        Assert.False(result.InvalidText);
    }

    [Fact]
    public void TruncationFailsClosedEvenWhenTheVisiblePrefixLooksBenign()
    {
        const string input = "/usr/bin/tool --mode scan --token synthetic-hidden-fragment";

        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 24);

        Assert.Equal(string.Empty, result.Value);
        Assert.True(result.Truncated);
        Assert.True(result.Redacted);
        Assert.True(result.Dropped);
        Assert.False(result.InvalidText);
    }

    [Theory]
    [InlineData("/usr/bin/tool --token synthetic\0control-fragment")]
    [InlineData("/usr/bin/tool --token synthetic\nline-fragment")]
    [InlineData("/usr/bin/tool --token synthetic\tseparator-fragment")]
    public void ControlCharactersFailClosed(string input)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        Assert.Equal(string.Empty, result.Value);
        Assert.True(result.InvalidText);
        Assert.True(result.Redacted);
        Assert.True(result.Dropped);
        Assert.False(result.Truncated);
    }

    [Fact]
    public void InvalidUtf16FailsClosedWithoutRetainingTheMalformedText()
    {
        var input = "/usr/bin/tool " + new string((char)0xD800, 1);

        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);

        Assert.Equal(string.Empty, result.Value);
        Assert.True(result.InvalidText);
        Assert.True(result.Redacted);
        Assert.True(result.Dropped);
        Assert.False(result.Truncated);
    }

    [Fact]
    public void ReplacementExpansionCannotExceedTheCallerBound()
    {
        const string input = "password=x";

        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, input.Length);

        Assert.True(result.Value.Length <= input.Length);
        Assert.Equal(string.Empty, result.Value);
        Assert.True(result.Redacted);
        Assert.True(result.Dropped);
    }

    [Fact]
    public void SerializedProcessEnvelopeContainsOnlyRedactedCommandLineCopies()
    {
        const string bearer = "synthetic-envelope-bearer-fragment";
        const string password = "synthetic-envelope-password-fragment";
        const string uriPassword = "synthetic-envelope-uri-fragment";
        var input = $"curl -H \"Authorization: Bearer {bearer}\" -u synthetic-user:{password} https://synthetic-user:{uriPassword}@example.invalid/path";
        var handled = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);
        Assert.False(handled.Dropped);

        var envelope = new EventEnvelope
        {
            EventId = Guid.Parse("11111111-1111-4111-8111-111111111111"),
            AgentId = "synthetic-agent",
            Hostname = "synthetic-host",
            Platform = "linux",
            Source = EventSources.InventoryDiff,
            SourceId = "linux-process-snapshot-diff",
            EventTime = DateTimeOffset.Parse("2026-07-16T00:00:00Z"),
            Message = "Synthetic process snapshot observation.",
            Normalized = new NormalizedEventFields
            {
                Category = "process",
                Action = "observed",
                ProcessCommandLine = handled.Value,
                Process = new ProcessTelemetryConcept { CommandLine = handled.Value }
            },
            Raw = JsonDefaults.ToJsonElement(new { command_line = handled.Value }),
            DataHandling = new DataHandlingMetadata
            {
                RedactionApplied = handled.Redacted,
                RedactedFields = ["raw.command_line", "normalized.process.command_line"]
            }
        };

        var serialized = JsonSerializer.Serialize(envelope, JsonDefaults.Options);
        Assert.DoesNotContain(bearer, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(password, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(uriPassword, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-user", serialized, StringComparison.Ordinal);
        Assert.True(handled.Redacted);
        Assert.Equal(3, CountOccurrences(handled.Value, "<redacted>"));
    }

    private static void AssertSuccessfulRedaction(SanitizedTelemetryText result, string expected)
    {
        Assert.Equal(expected, result.Value);
        Assert.True(result.Redacted);
        Assert.False(result.Dropped);
        Assert.False(result.Truncated);
        Assert.False(result.InvalidText);
        Assert.True(result.Value.Length <= 4096);
    }

    private static int CountOccurrences(string value, string fragment)
    {
        var count = 0;
        var offset = 0;
        while ((offset = value.IndexOf(fragment, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += fragment.Length;
        }
        return count;
    }
}
