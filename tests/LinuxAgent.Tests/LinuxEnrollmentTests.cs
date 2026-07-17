using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Services;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxEnrollmentTests
{
    [Fact]
    public async Task EnrollmentPersistsConfiguredSelfIntegrityBlock()
    {
        if (!OperatingSystem.IsLinux()) return;

        var root = Path.Combine(Path.GetTempPath(), $"challenger-linux-enrollment-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var configPath = Path.Combine(root, "agentsettings.json");
        var statePath = Path.Combine(root, "state.json");
        var previousConfigPath = Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG");
        var options = new LinuxAgentOptions
        {
            AgentId = "synthetic-linux-enrollment",
            ServerBaseUrl = new Uri("https://siem.example.invalid"),
            EnrollmentToken = "synthetic-enrollment-token",
            Journal = new JournalOptions
            {
                IncludeAccessibleUserJournals = true,
                TargetCoverageLevel = WindowsCoverageLevel.L3
            },
            SelfIntegrity = new SelfIntegrityOptions
            {
                Enabled = false,
                ApprovedPlanHash = $"sha256:{new string('a', 64)}",
                StartupDelaySeconds = 7,
                IntervalSeconds = 777,
                ScanTimeoutSeconds = 17,
                QueuePauseDepth = 4321,
                MaxEventsPerScan = 9,
                CleanupStateOnDisable = true,
                StatePath = Path.Combine(root, "self-integrity-state.json")
            },
            PassiveTelemetry = new PassiveTelemetryOptions
            {
                Enabled = false,
                ApprovedPlanHash = $"sha256:{new string('b', 64)}",
                StartupDelaySeconds = 8,
                ProcessPollIntervalSeconds = 18,
                NetworkPollIntervalSeconds = 19,
                HostMetricsIntervalSeconds = 61,
                ScanTimeoutSeconds = 6,
                QueuePauseDepth = 5432,
                MaxProcessesPerScan = 1234,
                MaxSocketsPerScan = 2345,
                MaxEventsPerScan = 345,
                MaxProcessReadBytesPerScan = 2 * 1024 * 1024,
                MaxNetworkReadBytesPerScan = 512 * 1024,
                MaxCommandLineBytes = 2048,
                MaxRawEventBytes = 8192,
                CleanupStateOnDisable = true,
                StatePath = Path.Combine(root, "passive-state.json")
            },
            L4Telemetry = new L4TelemetryOptions
            {
                Enabled = false,
                ApprovedPlanHash = $"sha256:{new string('c', 64)}",
                ApprovedBaselineHash = $"sha256:{new string('d', 64)}",
                StartupDelaySeconds = 9,
                PostureIntervalSeconds = 3600,
                SloSampleIntervalSeconds = 120,
                SloWindowMinutes = 20,
                ScanTimeoutSeconds = 12,
                QueuePauseDepth = 3210,
                MaxEventsPerScan = 42,
                CleanupStateOnDisable = true,
                StatePath = Path.Combine(root, "l4-state.json")
            },
            State = new StateOptions { Path = statePath },
            Queue = new QueueOptions { Path = Path.Combine(root, "queue.sqlite") }
        };

        try
        {
            await File.WriteAllTextAsync(configPath, "{}");
            Environment.SetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG", configPath);
            using var http = new HttpClient(new RegistrationHandler(options.AgentId))
            {
                BaseAddress = options.ServerBaseUrl
            };
            var service = new LinuxEnrollmentService(
                Options.Create(options),
                new SiemIngestClient(http, options),
                new LinuxStateStore(statePath),
                NullLogger<LinuxEnrollmentService>.Instance);

            await service.EnsureAsync("1.0.0", default);

            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(configPath));
            var persisted = document.RootElement.GetProperty("Agent").GetProperty("SelfIntegrity");
            Assert.False(persisted.GetProperty("Enabled").GetBoolean());
            Assert.Equal(options.SelfIntegrity.ApprovedPlanHash, persisted.GetProperty("ApprovedPlanHash").GetString());
            Assert.Equal(7, persisted.GetProperty("StartupDelaySeconds").GetInt32());
            Assert.Equal(777, persisted.GetProperty("IntervalSeconds").GetInt32());
            Assert.Equal(17, persisted.GetProperty("ScanTimeoutSeconds").GetInt32());
            Assert.Equal(4321, persisted.GetProperty("QueuePauseDepth").GetInt32());
            Assert.Equal(9, persisted.GetProperty("MaxEventsPerScan").GetInt32());
            Assert.True(persisted.GetProperty("CleanupStateOnDisable").GetBoolean());
            Assert.Equal(options.SelfIntegrity.StatePath, persisted.GetProperty("StatePath").GetString());
            var passive = document.RootElement.GetProperty("Agent").GetProperty("PassiveTelemetry");
            Assert.False(passive.GetProperty("Enabled").GetBoolean());
            Assert.Equal(options.PassiveTelemetry.ApprovedPlanHash, passive.GetProperty("ApprovedPlanHash").GetString());
            Assert.Equal(18, passive.GetProperty("ProcessPollIntervalSeconds").GetInt32());
            Assert.Equal(19, passive.GetProperty("NetworkPollIntervalSeconds").GetInt32());
            Assert.Equal(61, passive.GetProperty("HostMetricsIntervalSeconds").GetInt32());
            Assert.Equal(1234, passive.GetProperty("MaxProcessesPerScan").GetInt32());
            Assert.Equal(2345, passive.GetProperty("MaxSocketsPerScan").GetInt32());
            Assert.True(passive.GetProperty("CleanupStateOnDisable").GetBoolean());
            Assert.Equal(options.PassiveTelemetry.StatePath, passive.GetProperty("StatePath").GetString());
            var l4 = document.RootElement.GetProperty("Agent").GetProperty("L4Telemetry");
            Assert.False(l4.GetProperty("Enabled").GetBoolean());
            Assert.Equal(options.L4Telemetry.ApprovedPlanHash, l4.GetProperty("ApprovedPlanHash").GetString());
            Assert.Equal(options.L4Telemetry.ApprovedBaselineHash, l4.GetProperty("ApprovedBaselineHash").GetString());
            Assert.Equal(3600, l4.GetProperty("PostureIntervalSeconds").GetInt32());
            Assert.Equal(120, l4.GetProperty("SloSampleIntervalSeconds").GetInt32());
            Assert.Equal(20, l4.GetProperty("SloWindowMinutes").GetInt32());
            Assert.Equal(3210, l4.GetProperty("QueuePauseDepth").GetInt32());
            Assert.Equal(42, l4.GetProperty("MaxEventsPerScan").GetInt32());
            Assert.True(l4.GetProperty("CleanupStateOnDisable").GetBoolean());
            Assert.Equal(options.L4Telemetry.StatePath, l4.GetProperty("StatePath").GetString());
            var journal = document.RootElement.GetProperty("Agent").GetProperty("Journal");
            Assert.True(journal.GetProperty("IncludeAccessibleUserJournals").GetBoolean());
            Assert.Equal(WindowsCoverageLevel.L3.ToString(), journal.GetProperty("TargetCoverageLevel").GetString());
            Assert.Equal(string.Empty, document.RootElement.GetProperty("Agent").GetProperty("EnrollmentToken").GetString());
            Assert.DoesNotContain("synthetic-enrollment-token", await File.ReadAllTextAsync(configPath), StringComparison.Ordinal);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(configPath));
        }
        finally
        {
            Environment.SetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG", previousConfigPath);
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class RegistrationHandler(string agentId) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("/api/v1/agents/register", request.RequestUri?.AbsolutePath);
            Assert.True(request.Headers.Contains("X-Enrollment-Token"));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new AgentRegistrationResponse
                {
                    AgentId = agentId,
                    ApiToken = "synthetic-agent-token",
                    RegisteredAt = DateTimeOffset.Parse("2026-01-01T00:00:00Z")
                }, options: JsonDefaults.Options)
            });
        }
    }
}
