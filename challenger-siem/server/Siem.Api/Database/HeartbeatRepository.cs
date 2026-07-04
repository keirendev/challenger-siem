using Challenger.Siem.Contracts.V1;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed class HeartbeatRepository(NpgsqlDataSource dataSource)
{
    public async Task InsertHeartbeatAsync(HeartbeatRequest request, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into agent_heartbeats (agent_id, hostname, agent_version, os, last_event_time, queue_depth, cpu_percent, memory_mb)
                values (@agent_id, @hostname, @agent_version, @os, @last_event_time, @queue_depth, @cpu_percent, @memory_mb);
                """;
            command.Parameters.AddWithValue("agent_id", request.AgentId);
            command.Parameters.AddWithValue("hostname", request.Hostname);
            command.Parameters.AddWithValue("agent_version", request.AgentVersion);
            command.Parameters.AddWithValue("os", request.Os);
            command.Parameters.AddWithValue("last_event_time", request.LastEventTime.HasValue ? request.LastEventTime.Value.ToUniversalTime() : (object)DBNull.Value);
            command.Parameters.AddWithValue("queue_depth", request.QueueDepth);
            command.Parameters.AddWithValue("cpu_percent", request.CpuPercent.HasValue ? request.CpuPercent.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("memory_mb", request.MemoryMb.HasValue ? request.MemoryMb.Value : (object)DBNull.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                update agents
                set hostname = @hostname,
                    agent_version = @agent_version,
                    last_seen = now(),
                    updated_at = now()
                where agent_id = @agent_id;
                """;
            command.Parameters.AddWithValue("agent_id", request.AgentId);
            command.Parameters.AddWithValue("hostname", request.Hostname);
            command.Parameters.AddWithValue("agent_version", request.AgentVersion);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }
}
