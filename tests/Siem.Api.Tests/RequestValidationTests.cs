using System.Text.Json;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Contracts.V1;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class RequestValidationTests
{
    [Fact]
    public void ValidateBatchAcceptsValidWindowsEventBatch()
    {
        var batch = CreateValidBatch();

        var errors = RequestValidation.ValidateBatch(batch, maxEventsPerBatch: 500);

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateBatchRejectsMismatchedEventAgentId()
    {
        var valid = CreateValidBatch();
        var invalidEvent = valid.Events[0] with { AgentId = "other-agent" };
        var batch = valid with { Events = new[] { invalidEvent } };

        var errors = RequestValidation.ValidateBatch(batch, maxEventsPerBatch: 500);

        Assert.Contains("events[0].agent_id", errors.Keys);
    }

    [Fact]
    public void ValidateBatchRejectsOversizedBatch()
    {
        var valid = CreateValidBatch();
        var events = Enumerable.Range(0, 2)
            .Select(index => valid.Events[0] with { EventId = Guid.NewGuid(), RecordId = index + 1 })
            .ToArray();
        var batch = valid with { Events = events };

        var errors = RequestValidation.ValidateBatch(batch, maxEventsPerBatch: 1);

        Assert.Contains(nameof(IngestBatchRequest.Events), errors.Keys);
    }

    [Fact]
    public void ValidateRegistrationRequiresAgentIdentity()
    {
        var request = new AgentRegistrationRequest
        {
            AgentId = "",
            Hostname = "WIN11-TEST",
            MachineGuid = "machine-guid",
            OsVersion = "Windows 11",
            AgentVersion = "0.1.0"
        };

        var errors = RequestValidation.ValidateRegistration(request);

        Assert.Contains(nameof(AgentRegistrationRequest.AgentId), errors.Keys);
    }

    private static IngestBatchRequest CreateValidBatch()
    {
        return new IngestBatchRequest
        {
            AgentId = "win11-test-001",
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = new[]
            {
                new EventEnvelope
                {
                    EventId = Guid.NewGuid(),
                    AgentId = "win11-test-001",
                    Hostname = "WIN11-TEST",
                    Source = EventSources.WindowsEventLog,
                    Channel = "Security",
                    Provider = "Microsoft-Windows-Security-Auditing",
                    WindowsEventId = 4625,
                    RecordId = 123456,
                    EventTime = DateTimeOffset.UtcNow,
                    IngestTime = null,
                    Severity = "audit_failure",
                    Message = "An account failed to log on.",
                    Raw = JsonSerializer.SerializeToElement(new { event_data = new { target_user_name = "alice" } })
                }
            }
        };
    }
}
