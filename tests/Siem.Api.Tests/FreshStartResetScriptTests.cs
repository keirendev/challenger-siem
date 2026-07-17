using System.Diagnostics;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class FreshStartResetScriptTests(IntegrationTestDatabase database)
{
    [Fact]
    public async Task FreshStartResetDefaultsToDryRunForLocalArtifactsOnly()
    {
        var result = await RunResetAsync("--local-artifacts-only");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("mode=dry-run", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("database_reset=skipped", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("local_artifacts=dry-run", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("artifact_secret_config_preserved=true", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("execute_requires=--execute --confirm RESET-TEST-ENVIRONMENT --i-understand-this-deletes-test-data", result.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("ConnectionStrings__SiemDatabase", result.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("Auth__ReviewToken", result.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("api_token", result.Stdout, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FreshStartResetExecuteRequiresConfirmationPhraseAndAssertion()
    {
        var missingConfirmation = await RunResetAsync("--local-artifacts-only", "--execute", "--i-understand-this-deletes-test-data");
        Assert.NotEqual(0, missingConfirmation.ExitCode);
        Assert.Contains("--execute requires --confirm 'RESET-TEST-ENVIRONMENT'", missingConfirmation.Stderr, StringComparison.Ordinal);

        var missingAssertion = await RunResetAsync("--local-artifacts-only", "--execute", "--confirm", "RESET-TEST-ENVIRONMENT");
        Assert.NotEqual(0, missingAssertion.ExitCode);
        Assert.Contains("--execute requires --i-understand-this-deletes-test-data", missingAssertion.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FreshStartResetRefusesUnsafeDatabaseTargetsWithoutLeakingConnectionString()
    {
        const string secret = "super-secret-reset-test-password";
        var result = await RunResetAsync(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings__SiemDatabase"] = $"Host=db.example.invalid;Database=production;Username=siem;Password={secret}",
                ["CHALLENGER_SIEM_DATABASE"] = null
            },
            "--execute",
            "--confirm",
            "RESET-TEST-ENVIRONMENT",
            "--i-understand-this-deletes-test-data");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Refusing full reset: target database is not classified as local/disposable", result.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, result.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, result.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("Password=", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FreshStartResetScriptDocumentsSecretPreservationAndAvoidsBroadLocalDeletion()
    {
        var script = File.ReadAllText(FindRepositoryFile("scripts/reset-test-environment.sh"));

        Assert.Contains("CONFIRM_PHRASE = \"RESET-TEST-ENVIRONMENT\"", script, StringComparison.Ordinal);
        Assert.Contains("artifact_secret_config_preserved=true", script, StringComparison.Ordinal);
        Assert.Contains("--include-generated-agent-files", script, StringComparison.Ordinal);
        Assert.Contains("--include-platform-logs", script, StringComparison.Ordinal);
        Assert.Contains("platform_service_alive", script, StringComparison.Ordinal);
        Assert.Contains("CHALLENGER_SIEM_PLATFORM_SYSTEMD_UNIT", script, StringComparison.Ordinal);
        Assert.Contains("Refusing local artifact cleanup while the local platform appears live", script, StringComparison.Ordinal);
        Assert.Contains("database_target=local_disposable", script, StringComparison.Ordinal);
        Assert.Contains("preserved_detection_rules", script, StringComparison.Ordinal);
        Assert.DoesNotContain("glob(\".local/*\")", script, StringComparison.Ordinal);
        Assert.DoesNotContain("shutil.rmtree(ROOT / \".local\")", script, StringComparison.Ordinal);
        Assert.DoesNotContain(".local/dev.env", ExtractArtifactCandidateBlock(script), StringComparison.Ordinal);
        Assert.DoesNotContain(".local/winrm.env", ExtractArtifactCandidateBlock(script), StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task FreshStartResetCanExecuteAgainstOptInDisposablePostgresDatabase()
    {
        if (Environment.GetEnvironmentVariable("CHALLENGER_SIEM_RUN_FULL_RESET_TESTS") != "1")
        {
            return;
        }

        var connectionString = database.RequireConnectionString();
        if (!LooksLocalDisposable(connectionString))
        {
            return;
        }

        var agentId = $"fresh-reset-{Guid.NewGuid():N}";
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using (var seed = dataSource.CreateCommand("""
            insert into agents (agent_id, hostname, os_version, agent_version, status, api_token_hash)
            values (@agent_id, 'FRESH-RESET-HOST', 'Synthetic OS', '0.0.0-test', 'active', 'hash');
            insert into events (event_id, agent_id, hostname, source, channel, provider, windows_event_id, record_id, event_time, severity, message, raw_json)
            values (@event_id, @agent_id, 'FRESH-RESET-HOST', 'windows_event_log', 'System', 'SyntheticProvider', 6005, 1, now(), 'information', 'synthetic reset message', '{}'::jsonb);
            insert into soc_agent_sessions (session_id, title, provider, model, status, context_agent_id)
            values (@session_id, 'Synthetic reset session', 'Local', 'soc-agent-local-v1', 'open', @agent_id);
            insert into soc_agent_messages (session_id, role, content, provider, model)
            values (@session_id, 'soc_agent', 'synthetic reset answer', 'Local', 'soc-agent-local-v1');
            """))
        {
            seed.Parameters.AddWithValue("agent_id", agentId);
            seed.Parameters.AddWithValue("event_id", Guid.NewGuid());
            seed.Parameters.AddWithValue("session_id", Guid.NewGuid());
            await seed.ExecuteNonQueryAsync();
        }

        var dryRun = await RunResetAsync(
            new Dictionary<string, string?> { ["ConnectionStrings__SiemDatabase"] = connectionString },
            Array.Empty<string>());
        Assert.Equal(0, dryRun.ExitCode);
        Assert.Contains("database_reset=dry-run", dryRun.Stdout, StringComparison.Ordinal);
        Assert.Contains("agents=", dryRun.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic reset", dryRun.Stdout, StringComparison.OrdinalIgnoreCase);

        var execute = await RunResetAsync(
            new Dictionary<string, string?> { ["ConnectionStrings__SiemDatabase"] = connectionString },
            "--execute",
            "--confirm",
            "RESET-TEST-ENVIRONMENT",
            "--i-understand-this-deletes-test-data");
        Assert.Equal(0, execute.ExitCode);
        Assert.Contains("database_rows_removed=true", execute.Stdout, StringComparison.Ordinal);
        Assert.Contains("schema_validation=passed", execute.Stdout, StringComparison.Ordinal);

        await using var count = dataSource.CreateCommand("select count(*) from agents;");
        Assert.Equal(0, Convert.ToInt32(await count.ExecuteScalarAsync()));
    }

    private static async Task<ScriptResult> RunResetAsync(params string[] arguments)
    {
        return await RunResetAsync(new Dictionary<string, string?>(), arguments);
    }

    private static async Task<ScriptResult> RunResetAsync(Dictionary<string, string?> environment, params string[] arguments)
    {
        var script = FindRepositoryFile("scripts/reset-test-environment.sh");
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

        foreach (var (key, value) in environment)
        {
            if (value is null)
            {
                startInfo.Environment.Remove(key);
            }
            else
            {
                startInfo.Environment[key] = value;
            }
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start reset script.");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return new ScriptResult(process.ExitCode, stdout, stderr);
    }

    private static string ExtractArtifactCandidateBlock(string script)
    {
        var start = script.IndexOf("def candidate_paths", StringComparison.Ordinal);
        var end = script.IndexOf("def path_size", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start, "candidate_paths block should exist.");
        return script[start..end];
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

    private static bool LooksLocalDisposable(string connectionString)
    {
        var lower = connectionString.ToLowerInvariant();
        var local = lower.Contains("host=localhost", StringComparison.Ordinal)
            || lower.Contains("host=127.0.0.1", StringComparison.Ordinal)
            || lower.Contains("server=localhost", StringComparison.Ordinal)
            || lower.Contains("server=127.0.0.1", StringComparison.Ordinal)
            || lower.StartsWith("postgres://localhost", StringComparison.Ordinal)
            || lower.StartsWith("postgresql://localhost", StringComparison.Ordinal)
            || lower.StartsWith("postgres://127.0.0.1", StringComparison.Ordinal)
            || lower.StartsWith("postgresql://127.0.0.1", StringComparison.Ordinal);
        var disposable = lower.Contains("test", StringComparison.Ordinal)
            || lower.Contains("dev", StringComparison.Ordinal)
            || lower.Contains("local", StringComparison.Ordinal)
            || lower.Contains("scratch", StringComparison.Ordinal)
            || lower.Contains("sandbox", StringComparison.Ordinal)
            || lower.Contains("challenger_siem", StringComparison.Ordinal);
        var unsafeName = lower.Contains("prod", StringComparison.Ordinal)
            || lower.Contains("production", StringComparison.Ordinal)
            || lower.Contains("client", StringComparison.Ordinal)
            || lower.Contains("customer", StringComparison.Ordinal)
            || lower.Contains("shared", StringComparison.Ordinal);
        return local && disposable && !unsafeName;
    }

    private sealed record ScriptResult(int ExitCode, string Stdout, string Stderr);
}
