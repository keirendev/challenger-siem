using System.Diagnostics;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class SyntheticDataCleanupScriptTests(IntegrationTestDatabase database)
{
    [PostgresFact]
    public async Task CleanupScriptDryRunExecuteAndSecondRunAreScopedAndIdempotent()
    {
        var connectionString = database.RequireConnectionString();
        var targetAgentId = $"cleanup-script-{Guid.NewGuid():N}";
        var keepAgentId = $"keep-script-{Guid.NewGuid():N}";
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await SeedAgentGraphAsync(dataSource, targetAgentId, "CLEANUP-SCRIPT-TARGET");
        await SeedAgentGraphAsync(dataSource, keepAgentId, "CLEANUP-SCRIPT-KEEP");

        var dryRun = await RunCleanupAsync(connectionString, "--no-defaults", "--agent-id", targetAgentId);
        Assert.Contains("mode=dry-run", dryRun, StringComparison.Ordinal);
        Assert.Contains("target_agents=1", dryRun, StringComparison.Ordinal);
        Assert.Equal(1, await CountAsync(dataSource, "agents", targetAgentId));
        Assert.Equal(1, await CountAsync(dataSource, "events", targetAgentId));

        var execute = await RunCleanupAsync(
            connectionString,
            "--no-defaults",
            "--agent-id",
            targetAgentId,
            "--execute",
            "--confirm",
            "DELETE-SYNTHETIC-DATA");
        Assert.Contains("mode=execute", execute, StringComparison.Ordinal);
        Assert.Contains("target_agents=1", execute, StringComparison.Ordinal);

        Assert.Equal(0, await CountAsync(dataSource, "agents", targetAgentId));
        Assert.Equal(0, await CountAsync(dataSource, "events", targetAgentId));
        Assert.Equal(0, await CountAsync(dataSource, "agent_heartbeats", targetAgentId));
        Assert.Equal(0, await CountAsync(dataSource, "source_health", targetAgentId));
        Assert.Equal(0, await CountAsync(dataSource, "asset_inventory_snapshots", targetAgentId));
        Assert.Equal(0, await CountAsync(dataSource, "coverage_exceptions", targetAgentId));
        Assert.Equal(0, await CountAsync(dataSource, "ingestion_errors", targetAgentId));
        Assert.Equal(0, await CountAsync(dataSource, "soc_agent_turns", targetAgentId, "context_agent_id"));
        Assert.Equal(0, await CountAsync(dataSource, "soc_agent_sessions", targetAgentId, "context_agent_id"));
        Assert.Equal(1, await CountAsync(dataSource, "agents", keepAgentId));
        Assert.Equal(1, await CountAsync(dataSource, "events", keepAgentId));

        var secondRun = await RunCleanupAsync(
            connectionString,
            "--no-defaults",
            "--agent-id",
            targetAgentId,
            "--execute",
            "--confirm",
            "DELETE-SYNTHETIC-DATA");
        Assert.Contains("target_agents=0", secondRun, StringComparison.Ordinal);
        Assert.Equal(1, await CountAsync(dataSource, "agents", keepAgentId));
    }

    private static async Task SeedAgentGraphAsync(NpgsqlDataSource dataSource, string agentId, string hostname)
    {
        var eventId = Guid.NewGuid();
        var alertId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        await using var command = dataSource.CreateCommand("""
            insert into agents (agent_id, hostname, machine_guid, os_version, agent_version, status, api_token_hash)
            values (@agent_id, @hostname, null, 'Synthetic OS', '0.8.0-test', 'active', 'synthetic-token-hash')
            on conflict (agent_id) do update set hostname = excluded.hostname, status = 'active', updated_at = now();

            insert into events (event_id, agent_id, hostname, source, channel, provider, windows_event_id, record_id, event_time, severity, message, raw_json)
            values (@event_id, @agent_id, @hostname, 'windows_event_log', 'System', 'SyntheticProvider', 6005, @record_id, now(), 'information', 'synthetic cleanup marker', '{}'::jsonb)
            on conflict (agent_id, event_id) do nothing;

            insert into agent_heartbeats (agent_id, hostname, agent_version, os, queue_depth)
            values (@agent_id, @hostname, '0.8.0-test', 'Synthetic OS', 1);

            insert into source_health (agent_id, source_id, display_name, channel, coverage_level, status, required_source, enabled)
            values (@agent_id, 'system', 'Windows System', 'System', 'L1', 'healthy', true, true)
            on conflict (agent_id, source_id) do update set status = excluded.status, updated_at = now();

            insert into asset_inventory_snapshots (agent_id, hostname, snapshot_type, collected_at, items, summary)
            values (@agent_id, @hostname, 'host_identity', now(), '[]'::jsonb, '{}'::jsonb);

            insert into coverage_exceptions (agent_id, source_id, reason, approved_by)
            values (@agent_id, 'system', 'synthetic cleanup test', 'synthetic-operator');

            insert into alerts (alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, summary)
            values (@alert_id, 'synthetic-cleanup-rule', 1, 'Synthetic cleanup alert', 'low', 'low', 'new', @agent_id, @hostname, 'synthetic summary')
            on conflict (alert_id) do nothing;

            insert into alert_evidence (alert_id, agent_id, event_id, event_time, channel, windows_event_id, summary)
            values (@alert_id, @agent_id, @event_id, now(), 'System', 6005, 'synthetic evidence');

            insert into ingestion_errors (agent_id, batch_id, event_id, error_code, error_message, payload)
            values (@agent_id, @batch_id, @event_id, 'synthetic_cleanup', 'synthetic validation error', '{}'::jsonb);

            insert into soc_agent_turns (provider, model, question, answer, tool_runs, citations, context_agent_id)
            values ('Local', 'soc-agent-local-v1', 'synthetic question', 'synthetic answer', '[]'::jsonb, '[]'::jsonb, @agent_id);

            insert into soc_agent_sessions (session_id, title, provider, model, status, context_agent_id)
            values (@session_id, 'Synthetic cleanup session', 'Local', 'soc-agent-local-v1', 'open', @agent_id)
            on conflict (session_id) do nothing;

            insert into soc_agent_messages (session_id, role, content, provider, model, tool_runs, citations)
            values (@session_id, 'soc_agent', 'synthetic message', 'Local', 'soc-agent-local-v1', '[]'::jsonb, '[]'::jsonb);
            """);
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("hostname", hostname);
        command.Parameters.AddWithValue("event_id", eventId);
        command.Parameters.AddWithValue("record_id", Random.Shared.NextInt64(1, long.MaxValue));
        command.Parameters.AddWithValue("alert_id", alertId);
        command.Parameters.AddWithValue("batch_id", Guid.NewGuid());
        command.Parameters.AddWithValue("session_id", sessionId);
        await command.ExecuteNonQueryAsync(CancellationToken.None);
    }

    private static async Task<int> CountAsync(NpgsqlDataSource dataSource, string tableName, string agentId, string columnName = "agent_id")
    {
        await using var command = dataSource.CreateCommand($"select count(*) from {tableName} where {columnName} = @agent_id;");
        command.Parameters.AddWithValue("agent_id", agentId);
        return Convert.ToInt32(await command.ExecuteScalarAsync(CancellationToken.None));
    }

    private static async Task<string> RunCleanupAsync(string connectionString, params string[] arguments)
    {
        var script = FindRepositoryFile("scripts/cleanup-synthetic-data.sh");
        var startInfo = new ProcessStartInfo(script)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        startInfo.Environment["ConnectionStrings__SiemDatabase"] = connectionString;
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start cleanup script.");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        Assert.True(process.ExitCode == 0, $"cleanup script exited with {process.ExitCode}: {stderr}");
        return stdout;
    }

    private static string FindRepositoryFile(string relativePath)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName, relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        throw new FileNotFoundException($"Could not locate repository file: {relativePath}");
    }
}
