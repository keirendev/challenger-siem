using Challenger.Siem.Contracts.V1;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed class AgentRepository(NpgsqlDataSource dataSource)
{
    public async Task UpsertAgentAsync(AgentRegistrationRequest request, string apiTokenHash, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into agents (agent_id, hostname, machine_guid, os_version, agent_version, first_seen, last_seen, status, api_token_hash)
            values (@agent_id, @hostname, @machine_guid, @os_version, @agent_version, now(), now(), 'active', @api_token_hash)
            on conflict (agent_id) do update set
                hostname = excluded.hostname,
                machine_guid = excluded.machine_guid,
                os_version = excluded.os_version,
                agent_version = excluded.agent_version,
                last_seen = now(),
                status = 'active',
                api_token_hash = excluded.api_token_hash,
                updated_at = now();
            """;
        command.Parameters.AddWithValue("agent_id", request.AgentId);
        command.Parameters.AddWithValue("hostname", request.Hostname);
        command.Parameters.AddWithValue("machine_guid", (object?)request.MachineGuid ?? DBNull.Value);
        command.Parameters.AddWithValue("os_version", request.OsVersion);
        command.Parameters.AddWithValue("agent_version", request.AgentVersion);
        command.Parameters.AddWithValue("api_token_hash", apiTokenHash);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> IsAgentTokenValidAsync(string agentId, string apiTokenHash, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select exists (
                select 1
                from agents
                where agent_id = @agent_id
                  and api_token_hash = @api_token_hash
                  and status = 'active'
            );
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("api_token_hash", apiTokenHash);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is bool valid && valid;
    }

    public async Task UpdateLastSeenAsync(string agentId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            update agents
            set last_seen = now(), updated_at = now()
            where agent_id = @agent_id;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
