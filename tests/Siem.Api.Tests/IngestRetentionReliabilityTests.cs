using System.Text.Json;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V2;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class IngestRetentionReliabilityTests(IntegrationTestDatabase database)
{
    [Fact]
    public void RetentionSqlSeparatesOptionalAndMandatoryPhasesWithoutComputedPrioritySort()
    {
        var source = File.ReadAllText(RepositoryFile("server", "Siem.Api", "Database", "RetentionRepository.cs"));

        Assert.Contains("mandatoryLinuxJournal: false", source, StringComparison.Ordinal);
        Assert.Contains("mandatoryLinuxJournal: true", source, StringComparison.Ordinal);
        Assert.Contains("mandatoryEventBatchBudget", source, StringComparison.Ordinal);
        Assert.DoesNotContain("order by priority asc", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DuplicateReplayUsesIndexedPreflightBeforeBoundedRaceSafeInsert()
    {
        var source = File.ReadAllText(RepositoryFile("server", "Siem.Api", "Database", "EventRepository.cs"));
        var lookup = source.IndexOf("and event_id = any(@event_ids)", StringComparison.Ordinal);
        var insert = source.IndexOf("insert into events (", StringComparison.Ordinal);

        Assert.True(lookup >= 0);
        Assert.True(insert > lookup);
        Assert.Contains("pendingEvents", source, StringComparison.Ordinal);
        Assert.Contains("on conflict (agent_id, event_id) do nothing", source, StringComparison.Ordinal);
        Assert.Contains("returning event_id", source, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task ContractMaximumIngestPreservesAcceptedAndDuplicateOrder()
    {
        await using var dataSource = NpgsqlDataSource.Create(database.RequireConnectionString());
        var agentId = $"synthetic-batched-ingest-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-BATCHED-INGEST";
        await InsertSyntheticAgentAsync(dataSource, agentId, hostname);
        var startedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        var events = Enumerable.Range(1, ContractLimits.MaxIngestEventsPerBatch)
            .Select(sequence => Envelope(
                agentId,
                hostname,
                $"synthetic_ingest_{sequence}",
                "synthetic-batched-ingest",
                EventSources.AgentHealth,
                startedAt.AddMilliseconds(sequence),
                sequence))
            .ToArray();
        var repository = new EventRepository(dataSource);

        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var first = await repository.StoreEventsAsync(new IngestBatchRequest
            {
                AgentId = agentId,
                BatchId = Guid.NewGuid(),
                SentAt = startedAt,
                Events = events
            }, deadline.Token);

            Assert.Equal(events.Length, first.Accepted);
            Assert.Equal(0, first.Duplicates);
            Assert.Equal(events.Select(item => item.EventId), first.AcceptedEventIds);
            Assert.Empty(first.DuplicateEventIds);

            var duplicate = await repository.StoreEventsAsync(new IngestBatchRequest
            {
                AgentId = agentId,
                BatchId = Guid.NewGuid(),
                SentAt = startedAt.AddSeconds(1),
                Events = events
            }, deadline.Token);

            Assert.Equal(0, duplicate.Accepted);
            Assert.Equal(events.Length, duplicate.Duplicates);
            Assert.Empty(duplicate.AcceptedEventIds);
            Assert.Equal(events.Select(item => item.EventId), duplicate.DuplicateEventIds);
        }
        finally
        {
            await DeleteSyntheticAgentAsync(dataSource, agentId);
        }
    }

    [PostgresFact]
    public async Task ScheduledRetentionUsesEstimatedAccountingAndDeletesOptionalEventsFirst()
    {
        await using var dataSource = NpgsqlDataSource.Create(database.RequireConnectionString());
        var agentId = $"synthetic-retention-priority-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-RETENTION-PRIORITY";
        await InsertSyntheticAgentAsync(dataSource, agentId, hostname);
        var now = DateTimeOffset.UtcNow;
        var mandatory = Envelope(
            agentId, hostname, "synthetic_mandatory", LinuxTelemetrySourceIds.JournalL1,
            EventSources.LinuxJournal, now.AddDays(-4_100), 1);
        var optional = Envelope(
            agentId, hostname, "synthetic_optional", "synthetic-optional-retention",
            EventSources.AgentHealth, now.AddDays(-4_000), 2);
        var retained = Envelope(
            agentId, hostname, "synthetic_retained", "synthetic-retained-event",
            EventSources.AgentHealth, now, 3);
        var repository = new EventRepository(dataSource);
        var retention = new RetentionRepository(dataSource, repository);
        var options = new ManagedRetentionOptions
        {
            Enabled = true,
            TargetRetentionDays = 3_650,
            ManagedCapacityBytes = ManagedRetentionOptions.HardManagedCapacityBytes,
            CleanupBatchSize = 1,
            MaxBatchesPerRun = 1
        };
        var runIds = new List<Guid>();

        try
        {
            var stored = await repository.StoreEventsAsync(new IngestBatchRequest
            {
                AgentId = agentId,
                BatchId = Guid.NewGuid(),
                SentAt = now,
                Events = [mandatory, optional, retained]
            }, CancellationToken.None);
            Assert.Equal(3, stored.Accepted);

            var directAccounting = await repository.GetManagedStorageAccountingAsync(
                options.ManagedCapacityBytes, CancellationToken.None, options.TargetRetentionDays);
            Assert.Equal("exact_live_rows", directAccounting.AccountingMode);

            var first = await retention.RunAsync(
                options,
                new RetentionRunRequest(DryRun: false, MaxBatches: 1),
                CancellationToken.None);
            runIds.Add(first.RunId);

            Assert.Equal("catalog_estimate", first.Before.AccountingMode);
            Assert.Equal("catalog_estimate", first.After?.AccountingMode);
            Assert.Equal(1, first.RemovedEventRows);
            Assert.Contains(first.Categories, item => item.Category == "optional_operational_events" && item.RemovedRows == 1);
            Assert.Null(await repository.GetEventAsync(agentId, optional.EventId, CancellationToken.None));
            Assert.NotNull(await repository.GetEventAsync(agentId, mandatory.EventId, CancellationToken.None));
            Assert.NotNull(await repository.GetEventAsync(agentId, retained.EventId, CancellationToken.None));

            var second = await retention.RunAsync(
                options,
                new RetentionRunRequest(DryRun: false, MaxBatches: 1),
                CancellationToken.None);
            runIds.Add(second.RunId);

            Assert.Equal(1, second.RemovedEventRows);
            Assert.Contains(second.Categories, item => item.Category == "mandatory_linux_journal" && item.RemovedRows == 1);
            Assert.Null(await repository.GetEventAsync(agentId, mandatory.EventId, CancellationToken.None));
            Assert.NotNull(await repository.GetEventAsync(agentId, retained.EventId, CancellationToken.None));
        }
        finally
        {
            await using (var cleanupReferences = dataSource.CreateCommand(
                "delete from managed_retention_removed_events where agent_id = @agent_id;"))
            {
                cleanupReferences.Parameters.AddWithValue("agent_id", agentId);
                await cleanupReferences.ExecuteNonQueryAsync();
            }
            foreach (var runId in runIds)
            {
                await using var cleanupRun = dataSource.CreateCommand(
                    "delete from managed_retention_runs where run_id = @run_id;");
                cleanupRun.Parameters.AddWithValue("run_id", runId);
                await cleanupRun.ExecuteNonQueryAsync();
            }
            await DeleteSyntheticAgentAsync(dataSource, agentId);
        }
    }

    [PostgresFact]
    public async Task ScheduledRetentionAdvancesMandatoryTailUnderSustainedOptionalBacklog()
    {
        await using var dataSource = NpgsqlDataSource.Create(database.RequireConnectionString());
        var agentId = $"synthetic-retention-fairness-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-RETENTION-FAIRNESS";
        await InsertSyntheticAgentAsync(dataSource, agentId, hostname);
        var now = DateTimeOffset.UtcNow;
        var mandatory = Enumerable.Range(1, 2)
            .Select(sequence => Envelope(
                agentId, hostname, $"synthetic_mandatory_{sequence}", LinuxTelemetrySourceIds.JournalL1,
                EventSources.LinuxJournal, now.AddDays(-4_100 + sequence), sequence))
            .ToArray();
        var optional = Enumerable.Range(1, 5)
            .Select(sequence => Envelope(
                agentId, hostname, $"synthetic_optional_{sequence}", "synthetic-optional-retention",
                EventSources.AgentHealth, now.AddDays(-4_000 + sequence), sequence + 10))
            .ToArray();
        var retained = Envelope(
            agentId, hostname, "synthetic_retained", "synthetic-retained-event",
            EventSources.AgentHealth, now, 100);
        var repository = new EventRepository(dataSource);
        var retention = new RetentionRepository(dataSource, repository);
        var options = new ManagedRetentionOptions
        {
            Enabled = true,
            TargetRetentionDays = 3_650,
            ManagedCapacityBytes = ManagedRetentionOptions.HardManagedCapacityBytes,
            CleanupBatchSize = 1,
            MaxBatchesPerRun = 4
        };
        Guid? runId = null;

        try
        {
            var stored = await repository.StoreEventsAsync(new IngestBatchRequest
            {
                AgentId = agentId,
                BatchId = Guid.NewGuid(),
                SentAt = now,
                Events = mandatory.Concat(optional).Append(retained).ToArray()
            }, CancellationToken.None);
            Assert.Equal(8, stored.Accepted);

            var result = await retention.RunAsync(
                options,
                new RetentionRunRequest(DryRun: false, MaxBatches: 4),
                CancellationToken.None);
            runId = result.RunId;

            Assert.Equal(4, result.RemovedEventRows);
            Assert.Equal("bounded_incomplete", result.Status);
            Assert.Equal(3, result.Categories.Single(item => item.Category == "optional_operational_events").RemovedRows);
            Assert.Equal(1, result.Categories.Single(item => item.Category == "mandatory_linux_journal").RemovedRows);
            Assert.Null(await repository.GetEventAsync(agentId, mandatory[0].EventId, CancellationToken.None));
            Assert.NotNull(await repository.GetEventAsync(agentId, mandatory[1].EventId, CancellationToken.None));
            Assert.Equal(2, (await Task.WhenAll(optional.Select(item => repository.GetEventAsync(
                agentId, item.EventId, CancellationToken.None)))).Count(item => item is not null));
            Assert.NotNull(await repository.GetEventAsync(agentId, retained.EventId, CancellationToken.None));
        }
        finally
        {
            await using (var cleanupReferences = dataSource.CreateCommand(
                "delete from managed_retention_removed_events where agent_id = @agent_id;"))
            {
                cleanupReferences.Parameters.AddWithValue("agent_id", agentId);
                await cleanupReferences.ExecuteNonQueryAsync();
            }
            if (runId.HasValue)
            {
                await using var cleanupRun = dataSource.CreateCommand(
                    "delete from managed_retention_runs where run_id = @run_id;");
                cleanupRun.Parameters.AddWithValue("run_id", runId.Value);
                await cleanupRun.ExecuteNonQueryAsync();
            }
            await DeleteSyntheticAgentAsync(dataSource, agentId);
        }
    }

    private static EventEnvelope Envelope(
        string agentId,
        string hostname,
        string eventCode,
        string sourceId,
        string source,
        DateTimeOffset eventTime,
        long sequence)
    {
        var raw = JsonSerializer.SerializeToElement(new { fixture = "synthetic-ingest-retention", sequence });
        var envelope = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = source,
            SourceId = sourceId,
            EventCode = eventCode,
            EventTime = eventTime,
            Severity = "information",
            Message = "Synthetic ingest and retention reliability evidence.",
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = eventTime, RecordedAt = eventTime },
            Deduplication = new EventDeduplicationMetadata
            {
                Inputs =
                [
                    DeduplicationInputs.AgentId,
                    DeduplicationInputs.SourceId,
                    DeduplicationInputs.CheckpointSequence,
                    DeduplicationInputs.EventCode
                ]
            },
            Raw = raw,
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw).Length
            }
        };
        return envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };
    }

    private static async Task InsertSyntheticAgentAsync(NpgsqlDataSource dataSource, string agentId, string hostname)
    {
        await using var command = dataSource.CreateCommand("""
            insert into agents(agent_id,hostname,os_version,agent_version,platform,host_id,api_token_hash)
            values(@agent_id,@hostname,'synthetic','2.10.0-test','linux',@host_id,'synthetic-hash');
            """);
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("hostname", hostname);
        command.Parameters.AddWithValue("host_id", $"{agentId}-host");
        await command.ExecuteNonQueryAsync();
    }

    private static async Task DeleteSyntheticAgentAsync(NpgsqlDataSource dataSource, string agentId)
    {
        await using var command = dataSource.CreateCommand("""
            delete from events where agent_id = @agent_id;
            delete from agents where agent_id = @agent_id;
            """);
        command.Parameters.AddWithValue("agent_id", agentId);
        await command.ExecuteNonQueryAsync();
    }

    private static string RepositoryFile(params string[] segments)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(new[] { current.FullName }.Concat(segments).ToArray());
            if (File.Exists(candidate)) return candidate;
            current = current.Parent;
        }
        throw new FileNotFoundException($"Could not locate repository file: {Path.Combine(segments)}");
    }
}
