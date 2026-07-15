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
            Assert.Equal(string.Empty, document.RootElement.GetProperty("Agent").GetProperty("EnrollmentToken").GetString());
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
