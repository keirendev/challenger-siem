using Challenger.Siem.Api.Storage;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V2;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class AgentLivenessMonitorTests(IntegrationTestDatabase database)
{
    [Fact]
    public void CadenceUsesLatestTwentyMedianIntervalsAndIgnoresOneOutlier()
    {
        var newest = DateTimeOffset.Parse("2026-08-01T12:00:00Z");
        var heartbeats = new List<DateTimeOffset> { newest };
        for (var index = 0; index < 20; index++)
            heartbeats.Add(heartbeats[^1].AddSeconds(index == 10 ? -240 : -60));

        Assert.Equal(TimeSpan.FromSeconds(60), AgentLivenessMonitorRepository.InferCadence(heartbeats));
        Assert.Equal(TimeSpan.FromMinutes(3), AgentLivenessMonitorRepository.AlertThreshold(TimeSpan.FromSeconds(60)));
    }

    [Theory]
    [InlineData(5, 30, 120)]
    [InlineData(60, 60, 180)]
    [InlineData(600, 300, 900)]
    public void CadenceAndThreeIntervalThresholdsAreClamped(int observedSeconds, int cadenceSeconds, int thresholdSeconds)
    {
        var now = DateTimeOffset.Parse("2026-08-01T12:00:00Z");
        var cadence = AgentLivenessMonitorRepository.InferCadence([now, now.AddSeconds(-observedSeconds)]);
        Assert.Equal(TimeSpan.FromSeconds(cadenceSeconds), cadence);
        Assert.Equal(TimeSpan.FromSeconds(thresholdSeconds), AgentLivenessMonitorRepository.AlertThreshold(cadence));
    }

    [Fact]
    public void EmptyHistoryFallsBackToSixtySecondsAndOutageIdentityIsStablePerBoundary()
    {
        Assert.Equal(TimeSpan.FromSeconds(60), AgentLivenessMonitorRepository.InferCadence([]));
        var boundary = DateTimeOffset.Parse("2026-08-01T12:00:00Z");
        var first = AgentLivenessMonitorRepository.OutageAlertId("synthetic-agent", boundary);
        Assert.Equal(first, AgentLivenessMonitorRepository.OutageAlertId("synthetic-agent", boundary));
        Assert.NotEqual(first, AgentLivenessMonitorRepository.OutageAlertId("synthetic-agent", boundary.AddMinutes(1)));
    }

    [Fact]
    public void MonitorStateSeparatesAttemptsSuccessAndFailureFreshness()
    {
        var state = new AgentLivenessMonitorState();
        var first = DateTimeOffset.Parse("2026-08-01T12:00:00Z");
        state.Attempt(first);
        state.Success(first.AddSeconds(1), 2);
        Assert.Equal("healthy", state.Current.Status);
        Assert.Equal(2, state.Current.ActiveOutageCount);
        state.Failure(first.AddSeconds(30), "monitor_run_failed");
        Assert.Equal(first.AddSeconds(1), state.Current.LastSuccessfulRunAt);
        Assert.Equal("error", state.Current.Status);
    }

    [PostgresFact]
    public async Task OutageAndHeartbeatRecoveryAreDatabaseIdempotentAndPreserveClosedAlerts()
    {
        await using var dataSource = NpgsqlDataSource.Create(database.RequireConnectionString());
        var agentId = $"liveness-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-LINUX-LIVENESS";
        var now = DateTimeOffset.UtcNow;
        await using (var agent = dataSource.CreateCommand("""
            insert into agents(agent_id, hostname, os_version, agent_version, api_token_hash, platform, host_id, first_seen, last_seen)
            values(@agent_id, @hostname, 'Synthetic Linux', '2.2.0-test', 'synthetic-hash', 'linux', @host_id, @first_seen, @last_seen);
            """))
        {
            agent.Parameters.AddWithValue("agent_id", agentId);
            agent.Parameters.AddWithValue("hostname", hostname);
            agent.Parameters.AddWithValue("host_id", $"{agentId}-host");
            agent.Parameters.AddWithValue("first_seen", now.AddHours(-1));
            agent.Parameters.AddWithValue("last_seen", now.AddMinutes(-4));
            await agent.ExecuteNonQueryAsync();
        }
        await using (var history = dataSource.CreateCommand("""
            insert into agent_heartbeats(agent_id, heartbeat_time, hostname, agent_version, os, queue_depth)
            select @agent_id, @newest - (value * interval '60 seconds'), @hostname, '2.2.0-test', 'Synthetic Linux', 0
            from generate_series(0, 20) as series(value);
            """))
        {
            history.Parameters.AddWithValue("agent_id", agentId);
            history.Parameters.AddWithValue("hostname", hostname);
            history.Parameters.AddWithValue("newest", now.AddMinutes(-4));
            await history.ExecuteNonQueryAsync();
        }

        var monitor = new AgentLivenessMonitorRepository(dataSource, new FixedTimeProvider(now));
        Assert.Equal(1, await monitor.RunOnceAsync(default));
        Assert.Equal(1, await monitor.RunOnceAsync(default));
        await using (var created = dataSource.CreateCommand("""
            select count(*)::int,
                   (select count(*)::int from alert_activities aa join alerts a on a.alert_id = aa.alert_id
                    where a.agent_id = @agent_id and aa.action = 'heartbeat_loss_detected')
            from alerts where agent_id = @agent_id and rule_id = 'tamper.agent-heartbeat-loss.linux';
            """))
        {
            created.Parameters.AddWithValue("agent_id", agentId);
            await using var reader = await created.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(1, reader.GetInt32(0));
            Assert.Equal(1, reader.GetInt32(1));
        }

        var heartbeats = new HeartbeatRepository(dataSource);
        var request = new HeartbeatRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            AgentVersion = "2.2.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = $"{agentId}-host",
            QueueDepth = 0,
            SourceHealth = []
        };
        await heartbeats.InsertHeartbeatAsync(request, default);
        await heartbeats.InsertHeartbeatAsync(request, default);
        await using (var recovered = dataSource.CreateCommand("""
            select a.status, a.disposition, a.closed_at,
                   (select count(*)::int from alert_activities where alert_id = a.alert_id and action = 'heartbeat_recovered')
            from alerts a where a.agent_id = @agent_id and a.rule_id = 'tamper.agent-heartbeat-loss.linux';
            """))
        {
            recovered.Parameters.AddWithValue("agent_id", agentId);
            await using var reader = await recovered.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(AlertStatuses.Resolved, reader.GetString(0));
            Assert.True(reader.IsDBNull(1));
            Assert.True(reader.IsDBNull(2));
            Assert.Equal(1, reader.GetInt32(3));
        }

        var closedId = Guid.NewGuid();
        await using (var closed = dataSource.CreateCommand("""
            insert into alerts(alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, summary, disposition, closed_at)
            values(@alert_id, 'tamper.agent-heartbeat-loss.linux', 1, 'Synthetic closed liveness alert', 'critical', 'medium', 'closed',
                   @agent_id, @hostname, 'Synthetic closed alert.', 'benign', now());
            """))
        {
            closed.Parameters.AddWithValue("alert_id", closedId);
            closed.Parameters.AddWithValue("agent_id", agentId);
            closed.Parameters.AddWithValue("hostname", hostname);
            await closed.ExecuteNonQueryAsync();
        }
        await heartbeats.InsertHeartbeatAsync(request, default);
        await using var preserved = dataSource.CreateCommand("select status, disposition from alerts where alert_id = @alert_id;");
        preserved.Parameters.AddWithValue("alert_id", closedId);
        await using var preservedReader = await preserved.ExecuteReaderAsync();
        Assert.True(await preservedReader.ReadAsync());
        Assert.Equal(AlertStatuses.Closed, preservedReader.GetString(0));
        Assert.Equal(AlertDispositions.Benign, preservedReader.GetString(1));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
