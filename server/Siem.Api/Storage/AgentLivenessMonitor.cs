using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V2;
using Microsoft.Extensions.Hosting;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Storage;

public sealed record AgentLivenessMonitorSnapshot(
    DateTimeOffset? LastAttemptAt,
    DateTimeOffset? LastSuccessfulRunAt,
    int ActiveOutageCount,
    string Status,
    string? ErrorCode);

public sealed class AgentLivenessMonitorState
{
    private AgentLivenessMonitorSnapshot current = new(null, null, 0, "starting", null);
    public AgentLivenessMonitorSnapshot Current => Volatile.Read(ref current);
    public void Attempt(DateTimeOffset now) => Volatile.Write(ref current, Current with { LastAttemptAt = now });
    public void Success(DateTimeOffset now, int outages) => Volatile.Write(ref current, new(now, now, outages, "healthy", null));
    public void Failure(DateTimeOffset now, string errorCode) => Volatile.Write(ref current, Current with
    {
        LastAttemptAt = now,
        Status = "error",
        ErrorCode = errorCode
    });
}

public sealed class AgentLivenessMonitorRepository(NpgsqlDataSource dataSource, TimeProvider timeProvider)
{
    public const string RuleId = "tamper.agent-heartbeat-loss.linux";
    public const int RuleVersion = 1;
    public static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);

    public async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        var agents = await ReadActiveAgentsAsync(cancellationToken);
        var now = timeProvider.GetUtcNow();
        var outages = 0;
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        foreach (var agent in agents)
        {
            var boundary = agent.HeartbeatTimes.Count > 0 ? agent.HeartbeatTimes[0] : agent.FirstSeen;
            var cadence = InferCadence(agent.HeartbeatTimes);
            var threshold = AlertThreshold(cadence);
            if (now - boundary < threshold) continue;
            if (await InsertOutageAsync(connection, agent.AgentId, agent.Hostname, boundary, cadence, threshold, cancellationToken))
                outages++;
        }
        return outages;
    }

    internal static TimeSpan InferCadence(IReadOnlyList<DateTimeOffset> newestFirst)
    {
        var intervals = newestFirst.Take(21).Zip(newestFirst.Skip(1).Take(20), (newer, older) => (newer - older).TotalSeconds)
            .Where(seconds => seconds > 0).Order().ToArray();
        if (intervals.Length == 0) return TimeSpan.FromSeconds(60);
        var median = intervals.Length % 2 == 1
            ? intervals[intervals.Length / 2]
            : (intervals[intervals.Length / 2 - 1] + intervals[intervals.Length / 2]) / 2;
        return TimeSpan.FromSeconds(Math.Clamp(median, 30, 300));
    }

    internal static TimeSpan AlertThreshold(TimeSpan cadence) =>
        TimeSpan.FromSeconds(Math.Clamp(cadence.TotalSeconds * 3, 120, 900));

    internal static Guid OutageAlertId(string agentId, DateTimeOffset outageBoundary)
    {
        var material = string.Join('\u001f', RuleId, RuleVersion.ToString(CultureInfo.InvariantCulture), agentId,
            outageBoundary.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        Span<byte> bytes = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes);
    }

    private async Task<IReadOnlyList<AgentHeartbeatHistory>> ReadActiveAgentsAsync(CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select a.agent_id, a.hostname, a.first_seen, h.heartbeat_time
            from agents a
            left join lateral (
                select heartbeat_time
                from agent_heartbeats
                where agent_id = a.agent_id
                order by heartbeat_time desc
                limit 21
            ) h on true
            where a.status = 'active'
            order by a.agent_id, h.heartbeat_time desc nulls last;
            """;
        var rows = new List<(string AgentId, string Hostname, DateTimeOffset FirstSeen, DateTimeOffset? Heartbeat)>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add((reader.GetString(0), reader.GetString(1), ReadTime(reader, 2), reader.IsDBNull(3) ? null : ReadTime(reader, 3)));
        }
        return rows.GroupBy(row => row.AgentId, StringComparer.Ordinal)
            .Select(group => new AgentHeartbeatHistory(
                group.Key,
                group.First().Hostname,
                group.First().FirstSeen,
                group.Where(row => row.Heartbeat.HasValue).Select(row => row.Heartbeat!.Value).ToArray()))
            .ToArray();
    }

    internal static async Task<bool> InsertOutageAsync(
        NpgsqlConnection connection,
        string agentId,
        string hostname,
        DateTimeOffset boundary,
        TimeSpan cadence,
        TimeSpan threshold,
        CancellationToken cancellationToken)
    {
        var alertId = OutageAlertId(agentId, boundary);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await AgentLivenessDatabaseLock.AcquireAsync(connection, transaction, agentId, cancellationToken);
        await using (var freshness = connection.CreateCommand())
        {
            freshness.Transaction = transaction;
            freshness.CommandText = """
                select exists (
                    select 1
                    from agent_heartbeats
                    where agent_id = @agent_id and heartbeat_time > @boundary
                );
                """;
            freshness.Parameters.AddWithValue("agent_id", agentId);
            freshness.Parameters.AddWithValue("boundary", boundary.ToUniversalTime());
            if (await freshness.ExecuteScalarAsync(cancellationToken) is true)
            {
                await transaction.CommitAsync(cancellationToken);
                return false;
            }
        }
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into alerts(alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, summary, affected_entities)
                values(@alert_id, @rule_id, @rule_version, 'Linux agent heartbeat loss', 'critical', 'medium', 'new', @agent_id, @hostname,
                       @summary, @affected_entities)
                on conflict(alert_id) do nothing;
                """;
            command.Parameters.AddWithValue("alert_id", alertId);
            command.Parameters.AddWithValue("rule_id", RuleId);
            command.Parameters.AddWithValue("rule_version", RuleVersion);
            command.Parameters.AddWithValue("agent_id", agentId);
            command.Parameters.AddWithValue("hostname", hostname);
            command.Parameters.AddWithValue("summary",
                $"No agent heartbeat arrived within the inferred bounded liveness threshold; cadence_seconds={(int)cadence.TotalSeconds}; threshold_seconds={(int)threshold.TotalSeconds}. API or database failure requires independent monitoring because this monitor cannot report its own platform outage.");
            var entities = command.Parameters.Add("affected_entities", NpgsqlDbType.Jsonb);
            entities.Value = JsonSerializer.Serialize(new[] { new EventEntity { Type = "agent", Value = agentId, Role = "affected" } });
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var activity = connection.CreateCommand())
        {
            activity.Transaction = transaction;
            activity.CommandText = """
                insert into alert_activities(activity_id, alert_id, actor, action, from_status, to_status, summary, idempotency_key)
                values(@activity_id, @alert_id, 'system:liveness', 'heartbeat_loss_detected', null, 'new',
                       'The bounded liveness monitor detected a heartbeat outage.', @idempotency_key)
                on conflict do nothing;
                """;
            activity.Parameters.AddWithValue("activity_id", Guid.NewGuid());
            activity.Parameters.AddWithValue("alert_id", alertId);
            activity.Parameters.AddWithValue("idempotency_key", $"liveness-loss:{alertId:N}");
            await activity.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    private static DateTimeOffset ReadTime(NpgsqlDataReader reader, int ordinal) => reader.GetValue(ordinal) switch
    {
        DateTimeOffset value => value.ToUniversalTime(),
        DateTime value => new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)),
        _ => throw new InvalidOperationException("Database timestamp had an unexpected type.")
    };

    private sealed record AgentHeartbeatHistory(
        string AgentId,
        string Hostname,
        DateTimeOffset FirstSeen,
        IReadOnlyList<DateTimeOffset> HeartbeatTimes);
}

public sealed class AgentLivenessMonitorHostedService(
    IServiceScopeFactory scopeFactory,
    AgentLivenessMonitorState state,
    TimeProvider timeProvider,
    ILogger<AgentLivenessMonitorHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(AgentLivenessMonitorRepository.ScanInterval, timeProvider);
        do
        {
            var now = timeProvider.GetUtcNow();
            state.Attempt(now);
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var repository = scope.ServiceProvider.GetRequiredService<AgentLivenessMonitorRepository>();
                state.Success(timeProvider.GetUtcNow(), await repository.RunOnceAsync(stoppingToken));
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                state.Failure(timeProvider.GetUtcNow(), "monitor_run_failed");
                logger.LogWarning(ex, "Agent liveness monitor pass failed; independent API/database monitoring remains required.");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
