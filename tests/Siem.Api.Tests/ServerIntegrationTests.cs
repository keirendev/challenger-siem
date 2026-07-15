using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.SocAgent;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class ServerIntegrationTests(IntegrationTestDatabase database)
{
    private const string EnrollmentToken = "integration-enrollment-token";
    private const string OperatorApiToken = "integration-operator-credential";

    [PostgresFact]
    public async Task OperatorLockoutExpiryRevocationRecoveryRotationAndImmutableAuditUsePostgres()
    {
        var connectionString=database.RequireConnectionString(); await using var dataSource=NpgsqlDataSource.Create(connectionString);
        var repository=new Challenger.Siem.Api.Database.OperatorRepository(dataSource,new Challenger.Siem.Api.Auth.OperatorPasswordHasher());
        var username=$"synthetic-operator-{Guid.NewGuid():N}"; var initial="Synthetic-Initial1!"; var recovered="Synthetic-Recovered2!";
        var op=await repository.CreateAsync(username,"Synthetic Operator",Challenger.Siem.Api.Auth.OperatorRoles.Analyst,initial,false,CancellationToken.None);
        var login=await repository.AuthenticatePasswordAsync(username,initial,CancellationToken.None);Assert.Equal("success",login.Status);Assert.NotNull(await repository.ValidateSessionAsync(login.SessionToken!,CancellationToken.None));
        await using(var expire=dataSource.CreateCommand("update operator_sessions set created_at=now()-interval '8 hours 1 second', expires_at=now()-interval '1 second' where session_id=@id")){expire.Parameters.AddWithValue("id",login.Session!.SessionId);await expire.ExecuteNonQueryAsync();}
        Assert.Null(await repository.ValidateSessionAsync(login.SessionToken!,CancellationToken.None));
        var active=await repository.AuthenticatePasswordAsync(username,initial,CancellationToken.None);await repository.ChangePasswordAsync(op.OperatorId,recovered,true,CancellationToken.None);Assert.Null(await repository.ValidateSessionAsync(active.SessionToken!,CancellationToken.None));
        for(var i=0;i<Challenger.Siem.Api.Database.OperatorRepository.LockoutAttempts;i++)await repository.AuthenticatePasswordAsync(username,"Synthetic-Wrong9!",CancellationToken.None);
        Assert.Equal("locked",(await repository.AuthenticatePasswordAsync(username,recovered,CancellationToken.None)).Status);
        await repository.ChangePasswordAsync(op.OperatorId,recovered,true,CancellationToken.None);Assert.Equal("success",(await repository.AuthenticatePasswordAsync(username,recovered,CancellationToken.None)).Status);
        var firstToken=await repository.RotateApiTokenAsync(op.OperatorId,CancellationToken.None);Assert.NotNull(await repository.AuthenticateApiTokenAsync(firstToken,CancellationToken.None));var secondToken=await repository.RotateApiTokenAsync(op.OperatorId,CancellationToken.None);Assert.Null(await repository.AuthenticateApiTokenAsync(firstToken,CancellationToken.None));Assert.NotNull(await repository.AuthenticateApiTokenAsync(secondToken,CancellationToken.None));
        long auditId;await using(var insert=dataSource.CreateCommand("insert into security_audit_events(operator_id,actor_username,action,outcome) values(@id,@user,'synthetic.test','success') returning audit_id")){insert.Parameters.AddWithValue("id",op.OperatorId);insert.Parameters.AddWithValue("user",username);auditId=Convert.ToInt64(await insert.ExecuteScalarAsync());}
        await using var mutate=dataSource.CreateCommand("delete from security_audit_events where audit_id=@id");mutate.Parameters.AddWithValue("id",auditId);var exception=await Assert.ThrowsAsync<PostgresException>(()=>mutate.ExecuteNonQueryAsync());Assert.Contains("append-only",exception.Message,StringComparison.OrdinalIgnoreCase);
    }

    [PostgresFact]
    public async Task RegistrationIngestHeartbeatSearchAndIngestionErrorsUsePostgres()
    {
        var connectionString = database.RequireConnectionString();
        var agentId = $"it-agent-{Guid.NewGuid():N}";
        var hostname = "IT-HOST";
        var now = DateTimeOffset.UtcNow;
        var eventId = Guid.NewGuid();
        var duplicateEventId = Guid.NewGuid();
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using (var invalidRegistration = await client.PostAsJsonAsync("/api/v1/agents/register", new AgentRegistrationRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            OsVersion = "Windows Test",
            AgentVersion = "0.3.0-test"
        }))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, invalidRegistration.StatusCode);
        }

        var firstToken = await RegisterAsync(client, agentId, hostname, "0.3.0-test");
        var secondToken = await RegisterAsync(client, agentId, hostname, "0.3.0-test");
        Assert.NotEqual(firstToken, secondToken);

        using (var oldTokenResponse = await SendJsonWithBearerAsync(
            client,
            "/api/v1/agents/heartbeat",
            CreateHeartbeat(agentId, hostname, queueDepth: 0),
            firstToken))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, oldTokenResponse.StatusCode);
        }

        var batch = new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = now,
            Events = new[]
            {
                CreateEvent(agentId, hostname, eventId, "System", 6005, now.AddMinutes(-2), "unique integration marker"),
                CreateEvent(agentId, hostname, duplicateEventId, "Application", 1000, now.AddMinutes(-1), "application marker")
            }
        };

        var ingest = await PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", batch, secondToken);
        Assert.Equal(2, ingest.Accepted);
        Assert.Equal(0, ingest.Duplicates);
        Assert.Contains(eventId, ingest.AcceptedEventIds);

        var duplicate = await PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", batch, secondToken);
        Assert.Equal(0, duplicate.Accepted);
        Assert.Equal(2, duplicate.Duplicates);
        Assert.Contains(eventId, duplicate.DuplicateEventIds);

        await PostJsonWithBearerAsync<JsonElement>(client, "/api/v1/agents/heartbeat", CreateHeartbeat(agentId, hostname, queueDepth: 7), secondToken);

        var search = await GetJsonWithOperatorApiTokenAsync<EventSearchResponse>(client,
            $"/api/v1/events?agent_id={Uri.EscapeDataString(agentId)}&hostname={hostname}&channel=System&windows_event_id=6005&category=system&action=observed&from={Uri.EscapeDataString(now.AddHours(-1).ToString("O"))}&to={Uri.EscapeDataString(now.AddHours(1).ToString("O"))}&keyword=unique&limit={EventSearchQuery.MaxLimit}");
        Assert.InRange(search.Events.Count, 1, 500);
        var stored = Assert.Single(search.Events, item => item.EventId == eventId);
        Assert.NotNull(stored.IngestTime);
        Assert.Equal("System", stored.Channel);
        Assert.Equal("system", stored.Normalized?.Category);
        Assert.Equal("Pacific Standard Time", stored.HostTimezone?.Id);
        Assert.Equal(-420, stored.HostTimezone?.UtcOffsetMinutes);

        var sourceHealth = await GetJsonWithOperatorApiTokenAsync<SourceHealthResponse>(client,
            $"/api/v1/source-health?agent_id={Uri.EscapeDataString(agentId)}");
        Assert.Contains(sourceHealth.Summaries, summary => summary.AgentId == agentId && summary.HostTimezone?.Id == "Pacific Standard Time");
        Assert.Contains(sourceHealth.Sources, source => source.SourceId == "system" && source.HostTimezone?.UtcOffsetMinutes == -420);
        Assert.Contains(sourceHealth.Sources, source => source.SourceId == "security" && source.Status == SourceHealthStatuses.Missing);

        var telemetryCoverage = await GetJsonWithOperatorApiTokenAsync<TelemetryCoverageResponse>(client,
            $"/api/v1/telemetry-coverage?agent_id={Uri.EscapeDataString(agentId)}&target_level=L2&lookback_hours=24");
        var agentCoverage = Assert.Single(telemetryCoverage.Agents);
        Assert.Equal(agentId, agentCoverage.AgentId);
        Assert.Equal("Pacific Standard Time", agentCoverage.HostTimezone?.Id);
        Assert.Equal(2, agentCoverage.RecentEventCount);
        Assert.True(agentCoverage.ExpectedSourceCount >= 15);
        Assert.Equal(1, agentCoverage.ReportedSourceCount);
        Assert.Contains(agentCoverage.Gaps, gap => gap.Contains("source-health row", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(agentCoverage.Sources, source => source.SourceId == "system" && source.RecentEventCount == 1);
        Assert.Contains(agentCoverage.DetectionPrerequisites, rule => rule.RuleId == "auth.bruteforce.windows" && rule.Status == "missing_prerequisites");

        var rules = await GetJsonWithOperatorApiTokenAsync<JsonElement>(client, "/api/v1/detections/rules");
        Assert.True(rules.GetProperty("rules").GetArrayLength() >= 10);

        var invalidBatchId = Guid.NewGuid();
        var invalidBatch = batch with
        {
            BatchId = invalidBatchId,
            Events = new[] { batch.Events[0] with { EventId = Guid.NewGuid(), AgentId = "other-agent" } }
        };
        using (var invalidIngest = await SendJsonWithBearerAsync(client, "/api/v1/ingest/events", invalidBatch, secondToken))
        {
            Assert.Equal(HttpStatusCode.BadRequest, invalidIngest.StatusCode);
        }

        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await AssertDatabaseStateAsync(dataSource, agentId, invalidBatchId);
    }

    [PostgresFact]
    public async Task ManagedRetentionDryRunExecuteRetryAndEvidenceStateUseBoundedScope()
    {
        var connectionString = database.RequireConnectionString();
        await ClearServerRetentionOverridesAsync(connectionString);
        var agentId = $"retention-agent-{Guid.NewGuid():N}";
        var hostname = "RETENTION-HOST";
        var oldOptionalId = Guid.NewGuid();
        var oldMandatoryId = Guid.NewGuid();
        var recentId = Guid.NewGuid();
        var alertId = Guid.NewGuid();
        var oldTime = DateTimeOffset.UtcNow.AddDays(-5);
        var recentTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        using var factory = CreateFactory(connectionString, new Dictionary<string, string?>
        {
            ["Storage:Retention:TargetRetentionDays"] = "1",
            ["Storage:Retention:ManagedCapacityBytes"] = "4096",
            ["Storage:Retention:CleanupBatchSize"] = "1",
            ["Storage:Retention:MaxBatchesPerRun"] = "10"
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var token = await RegisterAsync(client, agentId, hostname, "1.2.0-test");
        var batch = new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = new[]
            {
                CreateEvent(agentId, hostname, oldOptionalId, "Windows PowerShell", 4104, oldTime, "old optional retention"),
                CreateEvent(agentId, hostname, oldMandatoryId, "System", 6005, oldTime.AddMinutes(1), "old mandatory retention"),
                CreateEvent(agentId, hostname, recentId, "Microsoft-Windows-Sysmon/Operational", 1, recentTime, "recent optional retention")
            }
        };
        await PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", batch, token);

        await using (var dataSource = NpgsqlDataSource.Create(connectionString))
        {
            await using var alertCommand = dataSource.CreateCommand("""
                insert into alerts(alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, summary)
                values(@alert_id, 'synthetic.retention', 1, 'Synthetic retention alert', 'medium', 'medium', 'new', @agent_id, @hostname, 'Synthetic retention alert');
                insert into alert_evidence(alert_id, agent_id, event_id, event_time, channel, windows_event_id, summary)
                values(@alert_id, @agent_id, @old_event_id, @old_time, 'Windows PowerShell', 4104, 'old evidence'),
                      (@alert_id, @agent_id, @recent_event_id, @recent_time, 'Microsoft-Windows-Sysmon/Operational', 1, 'recent evidence');
                """);
            alertCommand.Parameters.AddWithValue("alert_id", alertId);
            alertCommand.Parameters.AddWithValue("agent_id", agentId);
            alertCommand.Parameters.AddWithValue("hostname", hostname);
            alertCommand.Parameters.AddWithValue("old_event_id", oldOptionalId);
            alertCommand.Parameters.AddWithValue("old_time", oldTime);
            alertCommand.Parameters.AddWithValue("recent_event_id", recentId);
            alertCommand.Parameters.AddWithValue("recent_time", recentTime);
            await alertCommand.ExecuteNonQueryAsync();
        }

        using (var unauth = await client.GetAsync("/api/v1/storage/retention/status"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unauth.StatusCode);
        }

        var dryRun = await PostJsonWithOperatorApiTokenAsync<RetentionRunSummary>(client, "/api/v1/storage/retention/run", new RetentionRunRequest(DryRun: true));
        Assert.Equal("dry_run", dryRun.Mode);
        Assert.Equal(0, dryRun.RemovedRows);
        Assert.Contains(dryRun.Categories, item => item.TableName == "events" && item.Category == "optional_extended_events" && item.EligibleRows >= 1);
        Assert.Contains(dryRun.Categories, item => item.TableName == "events" && item.Category == "mandatory_windows_event_log" && item.EligibleRows >= 1);
        Assert.DoesNotContain(dryRun.ManagedTables, table => table == "operators");
        Assert.Contains("operators", dryRun.ProtectedTables);

        var firstPass = await PostJsonWithOperatorApiTokenAsync<RetentionRunSummary>(client, "/api/v1/storage/retention/run", new RetentionRunRequest(DryRun: false, MaxBatches: 1));
        Assert.Equal("execute", firstPass.Mode);
        Assert.Equal(1, firstPass.RemovedEventRows);
        var secondPass = await PostJsonWithOperatorApiTokenAsync<RetentionRunSummary>(client, "/api/v1/storage/retention/run", new RetentionRunRequest(DryRun: false, MaxBatches: 1));
        Assert.Equal(1, secondPass.RemovedEventRows);

        var search = await GetJsonWithOperatorApiTokenAsync<EventSearchResponse>(client, $"/api/v1/events?agent_id={Uri.EscapeDataString(agentId)}&limit=10");
        Assert.DoesNotContain(search.Events, item => item.EventId == oldOptionalId);
        Assert.DoesNotContain(search.Events, item => item.EventId == oldMandatoryId);
        Assert.Contains(search.Events, item => item.EventId == recentId);

        var alert = await GetJsonWithOperatorApiTokenAsync<AlertRecord>(client, $"/api/v1/alerts/{alertId}");
        Assert.Contains(alert.Evidence, item => item.EventId == oldOptionalId && item.TelemetryRetentionState == "telemetry_removed_by_retention");
        Assert.Contains(alert.Evidence, item => item.EventId == recentId && item.TelemetryRetentionState == "telemetry_retained");

        await using (var dataSource = NpgsqlDataSource.Create(connectionString))
        await using (var command = dataSource.CreateCommand("select count(*) from operators where username = 'synthetic-admin';"))
        {
            Assert.Equal(1L, (long)(await command.ExecuteScalarAsync() ?? 0L));
        }
    }

    [PostgresFact]
    public async Task ManagedRetentionLockContentionAndEmergencyPreferOptionalTelemetry()
    {
        var connectionString = database.RequireConnectionString();
        await ClearServerRetentionOverridesAsync(connectionString);
        var agentId = $"emergency-agent-{Guid.NewGuid():N}";
        var hostname = "EMERGENCY-HOST";
        var optionalId = Guid.NewGuid();
        var mandatoryId = Guid.NewGuid();
        using var factory = CreateFactory(connectionString, new Dictionary<string, string?>
        {
            ["Storage:Retention:TargetRetentionDays"] = "30",
            ["Storage:Retention:ManagedCapacityBytes"] = "1024",
            ["Storage:Retention:CleanupBatchSize"] = "1",
            ["Storage:Retention:MaxBatchesPerRun"] = "1",
            ["Storage:Retention:EmergencyTargetPercent"] = "95"
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var token = await RegisterAsync(client, agentId, hostname, "1.2.0-test");
        var now = DateTimeOffset.UtcNow;
        await PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = now,
            Events = new[]
            {
                CreateEvent(agentId, hostname, optionalId, "Windows PowerShell", 4104, now.AddMinutes(-20), new string('o', 256)),
                CreateEvent(agentId, hostname, mandatoryId, "Security", 4624, now.AddMinutes(-10), new string('m', 256))
            }
        }, token);

        await using (var dataSource = NpgsqlDataSource.Create(connectionString))
        await using (var lockConnection = await dataSource.OpenConnectionAsync())
        {
            await using (var lockCommand = lockConnection.CreateCommand())
            {
                lockCommand.CommandText = "select pg_advisory_lock(197301100);";
                await lockCommand.ExecuteNonQueryAsync();
            }
            using var conflictRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/storage/retention/run")
            {
                Content = JsonContent.Create(new RetentionRunRequest(DryRun: false), options: JsonOptions.Default)
            };
            conflictRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", OperatorApiToken);
            using var conflict = await client.SendAsync(conflictRequest);
            Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
            await using var unlock = lockConnection.CreateCommand();
            unlock.CommandText = "select pg_advisory_unlock(197301100);";
            await unlock.ExecuteNonQueryAsync();
        }

        var emergency = await PostJsonWithOperatorApiTokenAsync<RetentionRunSummary>(client, "/api/v1/storage/retention/run", new RetentionRunRequest(DryRun: false, Emergency: true, MaxBatches: 1));
        Assert.Equal("emergency", emergency.Trigger);
        Assert.True(emergency.RemovedRows >= 1);
        Assert.All(emergency.Categories, item => Assert.StartsWith("optional_", item.Category, StringComparison.Ordinal));
        Assert.DoesNotContain(emergency.Categories, item => item.Category is "mandatory_windows_event_log" or "mandatory_linux_journal");

        var remaining = await GetJsonWithOperatorApiTokenAsync<EventSearchResponse>(client, $"/api/v1/events?agent_id={Uri.EscapeDataString(agentId)}&limit=10");
        Assert.Contains(remaining.Events, item => item.EventId == mandatoryId);
    }

    [PostgresFact]
    public async Task ManagedRetentionStatusAccountingAndSearchRemainResponsiveWithSyntheticVolume()
    {
        var connectionString = database.RequireConnectionString();
        await ClearServerRetentionOverridesAsync(connectionString);
        var agentId = $"volume-agent-{Guid.NewGuid():N}";
        var hostname = "VOLUME-HOST";
        using var factory = CreateFactory(connectionString, new Dictionary<string, string?>
        {
            ["Storage:Retention:TargetRetentionDays"] = "1",
            ["Storage:Retention:ManagedCapacityBytes"] = "1048576",
            ["Storage:Retention:CleanupBatchSize"] = "25",
            ["Storage:Retention:MaxBatchesPerRun"] = "4"
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var token = await RegisterAsync(client, agentId, hostname, "1.2.0-test");
        var oldTime = DateTimeOffset.UtcNow.AddDays(-10);
        for (var batchIndex = 0; batchIndex < 4; batchIndex++)
        {
            var events = Enumerable.Range(0, 25)
                .Select(index => CreateEvent(agentId, hostname, Guid.NewGuid(), "Application", 1000 + index, oldTime.AddSeconds(batchIndex * 25 + index), "volume retention"))
                .ToArray();
            await PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", new IngestBatchRequest { AgentId = agentId, BatchId = Guid.NewGuid(), SentAt = DateTimeOffset.UtcNow, Events = events }, token);
        }

        var status = await GetJsonWithOperatorApiTokenAsync<RetentionStatusResponse>(client, "/api/v1/storage/retention/status");
        Assert.True(status.Accounting.EventRows >= 100);
        Assert.Equal("expired_telemetry_present", status.RetentionLagState);

        var concurrentEventId = Guid.NewGuid();
        var started = DateTimeOffset.UtcNow;
        var cleanupTask = PostJsonWithOperatorApiTokenAsync<RetentionRunSummary>(client, "/api/v1/storage/retention/run", new RetentionRunRequest(DryRun: false));
        var ingestTask = PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = new[] { CreateEvent(agentId, hostname, concurrentEventId, "System", 6005, DateTimeOffset.UtcNow, "concurrent ingest retention") }
        }, token);
        await Task.WhenAll(cleanupTask, ingestTask);
        var cleanup = await cleanupTask;
        var cleanupElapsed = DateTimeOffset.UtcNow - started;
        Assert.True(cleanup.RemovedEventRows >= 100);
        Assert.Equal(1, (await ingestTask).Accepted);
        Assert.True(cleanupElapsed < TimeSpan.FromSeconds(20));

        var queryStarted = DateTimeOffset.UtcNow;
        var remaining = await GetJsonWithOperatorApiTokenAsync<EventSearchResponse>(client, $"/api/v1/events?agent_id={Uri.EscapeDataString(agentId)}&limit=10");
        Assert.Single(remaining.Events, item => item.EventId == concurrentEventId);
        Assert.True(DateTimeOffset.UtcNow - queryStarted < TimeSpan.FromSeconds(5));
    }

    [PostgresFact]
    public async Task PlatformCapabilitiesEndpointRequiresOperatorApiTokenAndReturnsSpecGapCatalog()
    {
        using var factory = CreateFactory(database.RequireConnectionString());
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using (var unauth = await client.GetAsync("/api/v1/platform/capabilities"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unauth.StatusCode);
        }

        var response = await GetJsonWithOperatorApiTokenAsync<PlatformCapabilitiesResponse>(client, "/api/v1/platform/capabilities");
        Assert.Equal(19, response.Capabilities.Count);
        Assert.Contains(response.Capabilities, item => item.CapabilityId == "SPEC-GAP-001");
        Assert.Contains(response.Capabilities, item => item.CapabilityId == "SPEC-GAP-019");
    }

    [PostgresFact]
    public async Task InvestigationGraphApisPersistNodesEdgesProposalsAndEnforceOperatorApiToken()
    {
        var connectionString = database.RequireConnectionString();
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using (var unauth = await client.GetAsync("/api/v1/graphs"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unauth.StatusCode);
        }

        var graph = await PostJsonWithOperatorApiTokenAsync<InvestigationGraphSummary>(client, "/api/v1/graphs", new InvestigationGraphCreateRequest
        {
            Title = "Synthetic investigation graph",
            Description = "Synthetic graph for API tests",
            Tags = new[] { "synthetic", "graph-test" }
        });
        Assert.NotEqual(Guid.Empty, graph.GraphId);
        Assert.Equal(1, graph.Version);

        var agentNode = await PostJsonWithOperatorApiTokenAsync<InvestigationGraphNode>(client, $"/api/v1/graphs/{graph.GraphId}/nodes", new InvestigationGraphNodeRequest
        {
            NodeType = "agent",
            Label = "synthetic-agent-node",
            ReferenceKind = "agent",
            ReferenceId = "graph-agent-001",
            LinkUrl = "/agents?agent_id=graph-agent-001",
            Notes = "Synthetic node only."
        });
        var noteNode = await PostJsonWithOperatorApiTokenAsync<InvestigationGraphNode>(client, $"/api/v1/graphs/{graph.GraphId}/nodes", new InvestigationGraphNodeRequest
        {
            NodeType = "note",
            Label = "analyst note",
            Notes = "Synthetic relationship note."
        });

        var edge = await PostJsonWithOperatorApiTokenAsync<InvestigationGraphEdge>(client, $"/api/v1/graphs/{graph.GraphId}/edges", new InvestigationGraphEdgeRequest
        {
            SourceNodeId = agentNode.NodeId,
            TargetNodeId = noteNode.NodeId,
            EdgeType = "annotates",
            Label = "documents"
        });
        Assert.Equal("annotates", edge.EdgeType);

        var proposal = await PostJsonWithOperatorApiTokenAsync<InvestigationGraphProposal>(client, $"/api/v1/graphs/{graph.GraphId}/proposals", new InvestigationGraphProposalRequest
        {
            Instruction = "Propose a synthetic note node."
        });
        Assert.Equal("pending", proposal.Status);
        Assert.Single(proposal.ProposedNodes);

        var applied = await PostJsonWithOperatorApiTokenAsync<InvestigationGraphProposal>(client, $"/api/v1/graphs/{graph.GraphId}/proposals/{proposal.ProposalId}/apply", new { });
        Assert.Equal("applied", applied.Status);

        var detail = await GetJsonWithOperatorApiTokenAsync<InvestigationGraphDetail>(client, $"/api/v1/graphs/{graph.GraphId}");
        Assert.Equal(graph.GraphId, detail.Graph.GraphId);
        Assert.True(detail.Nodes.Count >= 3);
        Assert.Contains(detail.Edges, item => item.EdgeId == edge.EdgeId);
        Assert.Contains(detail.Proposals, item => item.ProposalId == proposal.ProposalId && item.Status == "applied");

        var updated = await PutJsonWithOperatorApiTokenAsync<InvestigationGraphSummary>(client, $"/api/v1/graphs/{graph.GraphId}", new InvestigationGraphUpdateRequest
        {
            Title = "Synthetic investigation graph updated",
            Description = "Updated synthetic graph",
            Tags = new[] { "updated" },
            ExpectedVersion = detail.Graph.Version
        });
        Assert.Equal("Synthetic investigation graph updated", updated.Title);
        Assert.True(updated.Version > detail.Graph.Version);
    }

    [PostgresFact]
    public async Task SocAgentChatEndpointsPersistSessionAndKeepOneShotAskCompatible()
    {
        var connectionString = database.RequireConnectionString();
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var status = await GetJsonWithOperatorApiTokenAsync<SocAgentProviderStatusResponse>(client, "/api/v1/soc-agent/status");
        Assert.Equal("local", status.Status);
        Assert.False(status.RequiresConnection);

        var oneShot = await PostJsonWithOperatorApiTokenAsync<SocAgentAskResponse>(client, "/api/v1/soc-agent/ask", new SocAgentAskRequest
        {
            Question = "Summarize current SIEM posture."
        });
        Assert.Contains("soc-agent local SIEM assessment", oneShot.Answer, StringComparison.Ordinal);
        Assert.NotEmpty(oneShot.ToolRuns);

        var session = await PostJsonWithOperatorApiTokenAsync<SocAgentSessionSummary>(client, "/api/v1/soc-agent/sessions", new SocAgentSessionCreateRequest
        {
            Title = "Synthetic investigation"
        });
        Assert.NotEqual(Guid.Empty, session.SessionId);

        var chat = await PostJsonWithOperatorApiTokenAsync<SocAgentChatResponse>(client, $"/api/v1/soc-agent/sessions/{session.SessionId}/messages", new SocAgentChatRequest
        {
            Message = "List current coverage and alert priorities."
        });
        Assert.Equal(session.SessionId, chat.Session.SessionId);
        Assert.Equal("operator", chat.UserMessage.Role);
        Assert.Equal("soc_agent", chat.AssistantMessage.Role);
        Assert.NotEmpty(chat.AssistantMessage.ToolRuns);
        Assert.Contains("Recommended next steps", chat.AssistantMessage.Content, StringComparison.Ordinal);

        var detail = await GetJsonWithOperatorApiTokenAsync<SocAgentSessionDetailResponse>(client, $"/api/v1/soc-agent/sessions/{session.SessionId}");
        Assert.Equal(session.SessionId, detail.Session.SessionId);
        Assert.True(detail.Messages.Count >= 2);
        Assert.Contains(detail.Messages, message => message.Role == "operator");
        Assert.Contains(detail.Messages, message => message.Role == "soc_agent");
    }

    [PostgresFact]
    public async Task SocAgentSessionDeleteRequiresOperatorApiTokenAndCascadesMessages()
    {
        var connectionString = database.RequireConnectionString();
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using (var unauth = await client.DeleteAsync($"/api/v1/soc-agent/sessions/{Guid.NewGuid()}"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unauth.StatusCode);
        }

        var session = await PostJsonWithOperatorApiTokenAsync<SocAgentSessionSummary>(client, "/api/v1/soc-agent/sessions", new SocAgentSessionCreateRequest
        {
            Title = "Synthetic session deletion"
        });
        var chat = await PostJsonWithOperatorApiTokenAsync<SocAgentChatResponse>(client, $"/api/v1/soc-agent/sessions/{session.SessionId}/messages", new SocAgentChatRequest
        {
            Message = "Create synthetic messages for deletion."
        });
        Assert.Equal(session.SessionId, chat.Session.SessionId);

        var deleted = await DeleteJsonWithOperatorApiTokenAsync<SocAgentSessionDeleteResponse>(client, $"/api/v1/soc-agent/sessions/{session.SessionId}");
        Assert.True(deleted.Deleted);
        Assert.Equal("deleted", deleted.Status);
        Assert.Equal(session.SessionId, deleted.SessionId);
        Assert.DoesNotContain("Create synthetic messages", deleted.Message, StringComparison.OrdinalIgnoreCase);

        using (var missingDetail = await SendGetWithOperatorApiTokenAsync(client, $"/api/v1/soc-agent/sessions/{session.SessionId}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, missingDetail.StatusCode);
        }

        using (var secondDelete = await SendDeleteWithOperatorApiTokenAsync(client, $"/api/v1/soc-agent/sessions/{session.SessionId}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, secondDelete.StatusCode);
        }

        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using var command = dataSource.CreateCommand("""
            select
                (select count(*) from soc_agent_sessions where session_id = @session_id) as session_count,
                (select count(*) from soc_agent_messages where session_id = @session_id) as message_count;
            """);
        command.Parameters.AddWithValue("session_id", session.SessionId);
        await using var reader = await command.ExecuteReaderAsync(CancellationToken.None);
        Assert.True(await reader.ReadAsync(CancellationToken.None));
        Assert.Equal(0L, reader.GetInt64(0));
        Assert.Equal(0L, reader.GetInt64(1));
    }

    [PostgresFact]
    public async Task SocAgentSessionDeleteBlocksActiveRuns()
    {
        var connectionString = database.RequireConnectionString();
        var slowProvider = new SlowSocAgentModelProvider();
        using var factory = CreateFactory(
            connectionString,
            new Dictionary<string, string?>
            {
                ["SocAgent:Provider"] = "OpenAI",
                ["SocAgent:ProviderDisplayName"] = "OpenAI ChatGPT",
                ["SocAgent:AuthMode"] = "ApiKey",
                ["SocAgent:Model"] = "gpt-test",
                ["SocAgent:ExternalCallsEnabled"] = "true",
                ["SocAgent:OpenAiApiKey"] = "fake-openai-api-key-for-tests"
            },
            services =>
            {
                services.RemoveAll<ISocAgentModelProvider>();
                services.AddSingleton<ISocAgentModelProvider>(slowProvider);
            });
        using var webClient = await CreateAuthenticatedWebClientAsync(factory);
        using var reviewClient = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var start = await PostJsonAsync<SocAgentLiveRunStartResponse>(webClient, "/soc-agent/live/runs", new SocAgentLiveRunStartRequest
        {
            Message = "Start a synthetic active run before deletion."
        });

        using (var blocked = await SendDeleteWithOperatorApiTokenAsync(reviewClient, $"/api/v1/soc-agent/sessions/{start.Session.SessionId}"))
        {
            Assert.Equal(HttpStatusCode.Conflict, blocked.StatusCode);
            var body = await blocked.Content.ReadAsStringAsync(CancellationToken.None);
            Assert.Contains("run_active", body, StringComparison.Ordinal);
            Assert.DoesNotContain("Start a synthetic active run", body, StringComparison.OrdinalIgnoreCase);
        }

        await PostJsonAsync<SocAgentLiveRunCancelResponse>(webClient, $"/soc-agent/live/runs/{start.RunId}/cancel", new { });
        using var streamResponse = await webClient.GetAsync($"/soc-agent/live/runs/{start.RunId}/events?after=0");
        streamResponse.EnsureSuccessStatusCode();
        var events = ParseServerSentEvents(await streamResponse.Content.ReadAsStringAsync(CancellationToken.None));
        Assert.Contains(events, item => item.GetProperty("type").GetString() == "run_complete");
    }

    [PostgresFact]
    public async Task SocAgentLiveRunStreamsProgressAndPersistsConversation()
    {
        var connectionString = database.RequireConnectionString();
        using var factory = CreateFactory(connectionString);
        using var webClient = await CreateAuthenticatedWebClientAsync(factory);
        using var reviewClient = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var start = await PostJsonAsync<SocAgentLiveRunStartResponse>(webClient, "/soc-agent/live/runs", new SocAgentLiveRunStartRequest
        {
            Message = "Summarize current SIEM posture from live mode."
        });

        Assert.NotEqual(Guid.Empty, start.RunId);
        Assert.NotEqual(Guid.Empty, start.Session.SessionId);
        Assert.Equal("operator", start.UserMessage.Role);

        using var streamResponse = await webClient.GetAsync($"/soc-agent/live/runs/{start.RunId}/events?after=0");
        streamResponse.EnsureSuccessStatusCode();
        var stream = await streamResponse.Content.ReadAsStringAsync(CancellationToken.None);
        var events = ParseServerSentEvents(stream);

        Assert.Contains(events, item => item.GetProperty("type").GetString() == "run_started");
        Assert.Contains(events, item => item.GetProperty("type").GetString() == "tool_started");
        Assert.Contains(events, item => item.GetProperty("type").GetString() == "tool_finished");
        Assert.Contains(events, item => item.GetProperty("type").GetString() == "content_delta");
        Assert.Contains(events, item => item.GetProperty("type").GetString() == "run_complete");
        Assert.True(events.Where(item => item.GetProperty("type").GetString() != "resume_snapshot").Select(item => item.GetProperty("sequence").GetInt64()).SequenceEqual(
            events.Where(item => item.GetProperty("type").GetString() != "resume_snapshot").Select(item => item.GetProperty("sequence").GetInt64()).OrderBy(item => item)));

        var detail = await GetJsonWithOperatorApiTokenAsync<SocAgentSessionDetailResponse>(reviewClient, $"/api/v1/soc-agent/sessions/{start.Session.SessionId}");
        Assert.Equal(start.Session.SessionId, detail.Session.SessionId);
        Assert.Single(detail.Messages, message => message.Role == "operator");
        Assert.Single(detail.Messages, message => message.Role == "soc_agent");
        Assert.Contains(detail.Messages, message => message.Role == "soc_agent" && message.ToolRuns.Count > 0);
    }

    [PostgresFact]
    public async Task SocAgentLiveRunCancelRecordsCancelledMessage()
    {
        var connectionString = database.RequireConnectionString();
        var slowProvider = new SlowSocAgentModelProvider();
        using var factory = CreateFactory(
            connectionString,
            new Dictionary<string, string?>
            {
                ["SocAgent:Provider"] = "OpenAI",
                ["SocAgent:ProviderDisplayName"] = "OpenAI ChatGPT",
                ["SocAgent:AuthMode"] = "ApiKey",
                ["SocAgent:Model"] = "gpt-test",
                ["SocAgent:ExternalCallsEnabled"] = "true",
                ["SocAgent:OpenAiApiKey"] = "fake-openai-api-key-for-tests"
            },
            services =>
            {
                services.RemoveAll<ISocAgentModelProvider>();
                services.AddSingleton<ISocAgentModelProvider>(slowProvider);
            });
        using var webClient = await CreateAuthenticatedWebClientAsync(factory);
        using var reviewClient = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var start = await PostJsonAsync<SocAgentLiveRunStartResponse>(webClient, "/soc-agent/live/runs", new SocAgentLiveRunStartRequest
        {
            Message = "Start an external provider turn that will be cancelled."
        });

        var cancel = await PostJsonAsync<SocAgentLiveRunCancelResponse>(webClient, $"/soc-agent/live/runs/{start.RunId}/cancel", new { });
        Assert.Equal(start.RunId, cancel.RunId);
        Assert.True(cancel.Cancelled || cancel.Status is "cancel_requested" or "cancelled");

        using var streamResponse = await webClient.GetAsync($"/soc-agent/live/runs/{start.RunId}/events?after=0");
        streamResponse.EnsureSuccessStatusCode();
        var events = ParseServerSentEvents(await streamResponse.Content.ReadAsStringAsync(CancellationToken.None));
        Assert.Contains(events, item => item.GetProperty("type").GetString() == "run_cancel_requested");
        Assert.Contains(events, item => item.GetProperty("type").GetString() == "run_complete" && item.GetProperty("data").GetProperty("status").GetString() == "cancelled");

        var detail = await GetJsonWithOperatorApiTokenAsync<SocAgentSessionDetailResponse>(reviewClient, $"/api/v1/soc-agent/sessions/{start.Session.SessionId}");
        Assert.Contains(detail.Messages, message => message.Role == "soc_agent" && message.ErrorCode == "cancelled");
    }

    [PostgresFact]
    public async Task SocAgentChatUsesConfiguredExternalProviderWhenConnected()
    {
        var connectionString = database.RequireConnectionString();
        var fakeProvider = new FakeSocAgentModelProvider("Fake official provider answer with citations preserved.");
        using var factory = CreateFactory(
            connectionString,
            new Dictionary<string, string?>
            {
                ["SocAgent:Provider"] = "OpenAI",
                ["SocAgent:ProviderDisplayName"] = "OpenAI ChatGPT",
                ["SocAgent:AuthMode"] = "ApiKey",
                ["SocAgent:Model"] = "gpt-test",
                ["SocAgent:ExternalCallsEnabled"] = "true",
                ["SocAgent:OpenAiApiKey"] = "fake-openai-api-key-for-tests"
            },
            services =>
            {
                services.RemoveAll<ISocAgentModelProvider>();
                services.AddSingleton<ISocAgentModelProvider>(fakeProvider);
            });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var status = await GetJsonWithOperatorApiTokenAsync<SocAgentProviderStatusResponse>(client, "/api/v1/soc-agent/status");
        Assert.Equal("connected", status.Status);
        Assert.False(status.RequiresConnection);
        Assert.True(status.DataMayLeaveLocalSiem);

        var session = await PostJsonWithOperatorApiTokenAsync<SocAgentSessionSummary>(client, "/api/v1/soc-agent/sessions", new SocAgentSessionCreateRequest
        {
            Title = "Synthetic external provider chat"
        });
        Assert.Equal("OpenAI", session.Provider);
        Assert.Equal("gpt-test", session.Model);

        var chat = await PostJsonWithOperatorApiTokenAsync<SocAgentChatResponse>(client, $"/api/v1/soc-agent/sessions/{session.SessionId}/messages", new SocAgentChatRequest
        {
            Message = "Summarize current posture with the official provider. api_key=should-not-leave"
        });

        Assert.Equal("OpenAI", chat.AssistantMessage.Provider);
        Assert.Equal("gpt-test", chat.AssistantMessage.Model);
        Assert.Contains("Fake official provider answer", chat.AssistantMessage.Content, StringComparison.Ordinal);
        Assert.Contains(chat.AssistantMessage.ToolRuns, tool => tool.ToolName == "external_model_provider");
        Assert.NotEmpty(chat.AssistantMessage.Citations);
        var providerRequest = fakeProvider.LastRequest ?? throw new InvalidOperationException("Fake provider was not called.");
        Assert.Contains("Local SIEM tool assessment", providerRequest.Prompt, StringComparison.Ordinal);
        Assert.Contains("api_key=<redacted>", providerRequest.Prompt, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fake-openai-api-key", providerRequest.Prompt, StringComparison.OrdinalIgnoreCase);

        var detail = await GetJsonWithOperatorApiTokenAsync<SocAgentSessionDetailResponse>(client, $"/api/v1/soc-agent/sessions/{session.SessionId}");
        Assert.Contains(detail.Messages, message => message.Role == "soc_agent" && message.Provider == "OpenAI");
    }

    [PostgresFact]
    public async Task SocAgentStatusReportsOfficialSetupWhenExternalProviderIsNotConfigured()
    {
        using var factory = CreateFactory(
            database.RequireConnectionString(),
            new Dictionary<string, string?>
            {
                ["SocAgent:Provider"] = "OpenAI",
                ["SocAgent:ProviderDisplayName"] = "OpenAI ChatGPT",
                ["SocAgent:AuthMode"] = "ApiKey",
                ["SocAgent:ExternalCallsEnabled"] = "true",
                ["SocAgent:ProviderSetupUrl"] = "https://platform.openai.com/api-keys"
            });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var status = await GetJsonWithOperatorApiTokenAsync<SocAgentProviderStatusResponse>(client, "/api/v1/soc-agent/status");

        Assert.Equal("provider_not_configured", status.Status);
        Assert.True(status.RequiresConnection);
        Assert.Equal("https://platform.openai.com/api-keys", status.ConnectUrl);
    }

    [PostgresFact]
    public async Task LinuxL2NormalizedIngestSearchAndCoverageUsePortableV1Storage()
    {
        var connectionString = database.RequireConnectionString();
        var agentId = $"linux-l2-it-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-LINUX-01";
        var now = DateTimeOffset.UtcNow;
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var token = await RegisterLinuxAsync(client, agentId, hostname);
        await PostJsonWithBearerAsync<JsonElement>(client, "/api/v1/agents/heartbeat", CreateLinuxL2Heartbeat(agentId, hostname, now), token);

        var envelope = CreateLinuxPackageEvent(agentId, hostname, now);
        var ingest = await PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = now,
            Events = [envelope]
        }, token);
        Assert.Equal(1, ingest.Accepted);

        var query = $"/api/v1/events?agent_id={Uri.EscapeDataString(agentId)}&source=linux_journal&platform=linux&source_id={LinuxTelemetrySourceIds.PackageManagement}&category=package&action=install&user_name=synthetic-user&process_image=synthetic-package-tool&source_ip=192.0.2.44&service_name=synthetic-package.service&package_name=synthetic-package&limit=10";
        var search = await GetJsonWithOperatorApiTokenAsync<EventSearchResponse>(client, query);
        var stored = Assert.Single(search.Events, item => item.EventId == envelope.EventId);
        Assert.Equal("synthetic-package", stored.Normalized?.PackageName);
        Assert.Equal("synthetic-user", stored.Normalized?.User?.Name);
        Assert.Equal("/usr/bin/synthetic-package-tool", stored.Normalized?.Process?.Executable);
        Assert.Equal("192.0.2.44", stored.Normalized?.Network?.SourceIp);
        Assert.Equal(envelope.EventId, DeterministicEventIdentity.ComputeSha256Uuid(stored));

        var sourceHealth = await GetJsonWithOperatorApiTokenAsync<SourceHealthResponse>(client,
            $"/api/v1/source-health?agent_id={Uri.EscapeDataString(agentId)}&target_level=L2");
        var summary = Assert.Single(sourceHealth.Summaries);
        Assert.Equal(TelemetryPlatforms.Linux, summary.Platform);
        Assert.Contains(sourceHealth.Sources, source => source.SourceId == LinuxTelemetrySourceIds.PackageManagement
            && source.Requirement == SourceRequirementKinds.Mandatory
            && source.EventFamilyStatuses!["package_install"] == SourceEvidenceStatuses.Observed);
        Assert.Contains(sourceHealth.Sources, source => source.SourceId == LinuxTelemetrySourceIds.LoginSession
            && source.Status == SourceHealthStatuses.Missing);

        var coverage = await GetJsonWithOperatorApiTokenAsync<TelemetryCoverageResponse>(client,
            $"/api/v1/telemetry-coverage?agent_id={Uri.EscapeDataString(agentId)}&target_level=L2&lookback_hours=24");
        var agentCoverage = Assert.Single(coverage.Agents);
        Assert.Equal(TelemetryPlatforms.Linux, agentCoverage.Platform);
        Assert.Equal(LinuxTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L2).Count, agentCoverage.ExpectedSourceCount);
        Assert.Equal(1, Assert.Single(agentCoverage.Sources, source => source.SourceId == LinuxTelemetrySourceIds.PackageManagement).RecentEventCount);
        Assert.Empty(agentCoverage.DetectionPrerequisites);

        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using var command = dataSource.CreateCommand("select platform || ':' || host_id from agents where agent_id = @agent_id;");
        command.Parameters.AddWithValue("agent_id", agentId);
        Assert.Equal($"linux:host-{agentId}", Convert.ToString(await command.ExecuteScalarAsync(CancellationToken.None)));
    }

    [PostgresFact]
    public async Task DisabledAgentTokenIsRejectedUntilRegistrationReactivatesAgent()
    {
        var connectionString = database.RequireConnectionString();
        var agentId = $"reactivate-agent-{Guid.NewGuid():N}";
        var hostname = "REACTIVATE-HOST";
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var disabledToken = await RegisterAsync(client, agentId, hostname, "0.3.0-test");
        await SetAgentStatusAsync(connectionString, agentId, "disabled");

        using (var disabledHeartbeat = await SendJsonWithBearerAsync(
            client,
            "/api/v1/agents/heartbeat",
            CreateHeartbeat(agentId, hostname, queueDepth: 0),
            disabledToken))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, disabledHeartbeat.StatusCode);
        }

        var reactivatedToken = await RegisterAsync(client, agentId, hostname, "0.3.1-test");
        Assert.NotEqual(disabledToken, reactivatedToken);
        await PostJsonWithBearerAsync<JsonElement>(client, "/api/v1/agents/heartbeat", CreateHeartbeat(agentId, hostname, queueDepth: 1), reactivatedToken);

        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using var command = dataSource.CreateCommand("select status from agents where agent_id = @agent_id;");
        command.Parameters.AddWithValue("agent_id", agentId);
        var status = Convert.ToString(await command.ExecuteScalarAsync(CancellationToken.None));
        Assert.Equal("active", status);
    }

    private static WebApplicationFactory<Program> CreateFactory(
        string connectionString,
        IReadOnlyDictionary<string, string?>? overrides = null,
        Action<IServiceCollection>? configureServices = null)
    {
        EnsureTestOperator(connectionString);
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SiemDatabase"] = connectionString,
                    ["Auth:EnrollmentToken"] = EnrollmentToken,
                    ["Ingestion:MaxEventsPerBatch"] = "500",
                    ["SocAgent:Provider"] = "Local",
                    ["SocAgent:ProviderDisplayName"] = "Local soc-agent",
                    ["SocAgent:AuthMode"] = "Local",
                    ["SocAgent:Model"] = "soc-agent-local-v1",
                    ["SocAgent:ExternalCallsEnabled"] = "false"
                };

                if (overrides is not null)
                {
                    foreach (var item in overrides)
                    {
                        values[item.Key] = item.Value;
                    }
                }

                configuration.AddInMemoryCollection(values);
            });

            if (configureServices is not null)
            {
                builder.ConfigureServices(configureServices);
            }
        });
    }


    private static void EnsureTestOperator(string connectionString)
    {
        using var connection = new NpgsqlConnection(connectionString); connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "insert into operators(operator_id,username,normalized_username,display_name,role,password_hash,api_token_hash) values(@id,'synthetic-admin','SYNTHETIC-ADMIN','Synthetic Admin','admin',@password,@token) on conflict(normalized_username) do update set role='admin',password_hash=excluded.password_hash,api_token_hash=excluded.api_token_hash,enabled=true;";
        command.Parameters.AddWithValue("id", Guid.NewGuid());
        command.Parameters.AddWithValue("password", new Challenger.Siem.Api.Auth.OperatorPasswordHasher().Hash("Synthetic-Test1!"));
        command.Parameters.AddWithValue("token", Challenger.Siem.Api.Auth.OperatorSecrets.Hash(OperatorApiToken));
        command.ExecuteNonQuery();
    }

    private static async Task<HttpClient> CreateAuthenticatedWebClientAsync(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        var loginHtml = await client.GetStringAsync("/login", CancellationToken.None);
        var tokenMatch = Regex.Match(loginHtml, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"", RegexOptions.CultureInvariant);
        if (!tokenMatch.Success)
        {
            throw new InvalidOperationException("login page did not include an antiforgery token.");
        }

        using var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(tokenMatch.Groups[1].Value),
            ["Username"] = "synthetic-admin",
            ["Password"] = "Synthetic-Test1!",
            ["ReturnUrl"] = "/"
        }), CancellationToken.None);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return client;
    }

    private static async Task<string> RegisterAsync(HttpClient client, string agentId, string hostname, string agentVersion)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/register")
        {
            Content = JsonContent.Create(new AgentRegistrationRequest
            {
                AgentId = agentId,
                Hostname = hostname,
                MachineGuid = Guid.NewGuid().ToString("N"),
                OsVersion = "Windows Test",
                AgentVersion = agentVersion,
                HostTimezone = SyntheticPacificTimezone()
            }, options: JsonOptions.Default)
        };
        request.Headers.Add("X-Enrollment-Token", EnrollmentToken);

        using var response = await client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        var registration = await response.Content.ReadFromJsonAsync<AgentRegistrationResponse>(JsonOptions.Default, CancellationToken.None);
        return registration?.ApiToken ?? throw new InvalidOperationException("Registration response did not include a token.");
    }

    private static async Task<string> RegisterLinuxAsync(HttpClient client, string agentId, string hostname)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/register")
        {
            Content = JsonContent.Create(new AgentRegistrationRequest
            {
                AgentId = agentId,
                Hostname = hostname,
                OsVersion = "Synthetic Linux",
                AgentVersion = "1.1.0-test",
                Platform = TelemetryPlatforms.Linux,
                HostId = $"host-{agentId}"
            }, options: JsonOptions.Default)
        };
        request.Headers.Add("X-Enrollment-Token", EnrollmentToken);
        using var response = await client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        var registration = await response.Content.ReadFromJsonAsync<AgentRegistrationResponse>(JsonOptions.Default, CancellationToken.None);
        return registration?.ApiToken ?? throw new InvalidOperationException("Linux registration response did not include a token.");
    }

    private static async Task<T> PostJsonWithBearerAsync<T>(HttpClient client, string path, object body, string token)
    {
        using var response = await SendJsonWithBearerAsync(client, path, body, token);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, CancellationToken.None);
        return result ?? throw new InvalidOperationException($"Response from {path} was empty.");
    }

    private static async Task<HttpResponseMessage> SendJsonWithBearerAsync(HttpClient client, string path, object body, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body, options: JsonOptions.Default)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, CancellationToken.None);
    }

    private static async Task<T> GetJsonWithOperatorApiTokenAsync<T>(HttpClient client, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", OperatorApiToken);
        using var response = await client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, CancellationToken.None);
        return result ?? throw new InvalidOperationException($"Response from {path} was empty.");
    }

    private static async Task<HttpResponseMessage> SendGetWithOperatorApiTokenAsync(HttpClient client, string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", OperatorApiToken);
        return await client.SendAsync(request, CancellationToken.None);
    }

    private static async Task<T> PostJsonWithOperatorApiTokenAsync<T>(HttpClient client, string path, object body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body, options: JsonOptions.Default)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", OperatorApiToken);
        using var response = await client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, CancellationToken.None);
        return result ?? throw new InvalidOperationException($"Response from {path} was empty.");
    }

    private static async Task<T> PostJsonAsync<T>(HttpClient client, string path, object body)
    {
        using var response = await client.PostAsJsonAsync(path, body, JsonOptions.Default, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, CancellationToken.None);
        return result ?? throw new InvalidOperationException($"Response from {path} was empty.");
    }

    private static async Task<T> DeleteJsonWithOperatorApiTokenAsync<T>(HttpClient client, string path)
    {
        using var response = await SendDeleteWithOperatorApiTokenAsync(client, path);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, CancellationToken.None);
        return result ?? throw new InvalidOperationException($"Response from {path} was empty.");
    }

    private static async Task<HttpResponseMessage> SendDeleteWithOperatorApiTokenAsync(HttpClient client, string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Delete, path);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", OperatorApiToken);
        return await client.SendAsync(request, CancellationToken.None);
    }

    private static async Task<T> PutJsonWithOperatorApiTokenAsync<T>(HttpClient client, string path, object body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, path)
        {
            Content = JsonContent.Create(body, options: JsonOptions.Default)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", OperatorApiToken);
        using var response = await client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, CancellationToken.None);
        return result ?? throw new InvalidOperationException($"Response from {path} was empty.");
    }

    private static async Task SetAgentStatusAsync(string connectionString, string agentId, string status)
    {
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using var command = dataSource.CreateCommand("""
            update agents
            set status = @status, updated_at = now()
            where agent_id = @agent_id;
            """);
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("status", status);
        await command.ExecuteNonQueryAsync(CancellationToken.None);
    }

    private static HostTimezoneMetadata SyntheticPacificTimezone() => new()
    {
        Id = "Pacific Standard Time",
        DisplayName = "(UTC-08:00) Pacific Time (US & Canada)",
        StandardName = "Pacific Standard Time",
        DaylightName = "Pacific Daylight Time",
        BaseUtcOffsetMinutes = -480,
        UtcOffsetMinutes = -420,
        IsDaylightSavingTime = true
    };

    private static HeartbeatRequest CreateHeartbeat(string agentId, string hostname, int queueDepth)
    {
        return new HeartbeatRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            AgentVersion = "0.3.0-test",
            Os = "Windows Test",
            LastEventTime = DateTimeOffset.UtcNow,
            HostTimezone = SyntheticPacificTimezone(),
            QueueDepth = queueDepth,
            CpuPercent = null,
            MemoryMb = 123,
            ConfigHash = "synthetic-config-hash",
            QueueMetrics = new QueueSloMetrics
            {
                QueueDepth = queueDepth,
                PoisonDepth = 0,
                MaxSizeMb = 512,
                WarningSizePercent = 80
            },
            SourceHealth = new[]
            {
                new SourceHealthReport
                {
                    SourceId = "system",
                    DisplayName = "Windows System",
                    Channel = "System",
                    CoverageLevel = WindowsCoverageLevel.L1,
                    Status = SourceHealthStatuses.Healthy,
                    Required = true,
                    Enabled = true,
                    NewestRecordId = 1234,
                    HostTimezone = SyntheticPacificTimezone()
                }
            }
        };
    }

    private static HeartbeatRequest CreateLinuxL2Heartbeat(string agentId, string hostname, DateTimeOffset now)
    {
        var manifest = LinuxTelemetrySourceCatalog.All
            .Where(entry => entry.SourceId is LinuxTelemetrySourceIds.JournalL1 or LinuxTelemetrySourceIds.PackageManagement)
            .ToArray();
        var health = manifest.Select(entry => new SourceHealthReport
        {
            SourceId = entry.SourceId,
            Platform = entry.Platform,
            SourceKind = entry.SourceKind,
            DisplayName = entry.DisplayName,
            SourceNamespace = entry.SourceNamespace,
            Applicability = entry.Applicability,
            CoverageLevel = entry.CoverageLevel,
            Status = SourceHealthStatuses.Healthy,
            Required = entry.Required,
            Requirement = entry.Requirement,
            ApplicableRoles = entry.ApplicableRoles,
            Enabled = true,
            LastEventTime = now,
            CollectedCheckpoint = new SourceCheckpoint { Cursor = "s=synthetic-linux-l2;i=1", RecordedAt = now },
            AcknowledgedCheckpoint = new SourceCheckpoint { Cursor = "s=synthetic-linux-l2;i=1", RecordedAt = now },
            PrerequisiteStatuses = entry.Prerequisites.ToDictionary(item => item, _ => SourceEvidenceStatuses.Satisfied, StringComparer.Ordinal),
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(
                item => item,
                item => item == "package_install" ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved,
                StringComparer.Ordinal),
            Details = new Dictionary<string, string> { ["configured_coverage_level"] = "L2" }
        }).ToArray();
        return new HeartbeatRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            AgentVersion = "1.1.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = $"host-{agentId}",
            LastEventTime = now,
            QueueDepth = 0,
            MemoryMb = 100,
            ConfigHash = "synthetic-linux-l2-config",
            QueueMetrics = new QueueSloMetrics { QueueDepth = 0, PoisonDepth = 0, MaxSizeMb = 512, WarningSizePercent = 80 },
            SourceManifest = manifest,
            SourceHealth = health
        };
    }

    private static EventEnvelope CreateLinuxPackageEvent(string agentId, string hostname, DateTimeOffset eventTime)
    {
        var raw = JsonSerializer.SerializeToElement(new { action = "install", package = "synthetic-package" });
        var envelope = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.LinuxJournal,
            SourceId = LinuxTelemetrySourceIds.PackageManagement,
            EventCode = "package_install.install",
            Unit = "synthetic-package.service",
            EventTime = eventTime,
            Severity = "information",
            Message = "Synthetic package installed.",
            Checkpoint = new SourceCheckpoint { Cursor = "s=synthetic-linux-l2;i=package-1", EventTime = eventTime, RecordedAt = eventTime },
            Deduplication = new EventDeduplicationMetadata
            {
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointCursor]
            },
            Normalized = new NormalizedEventFields
            {
                Category = "package",
                Action = "install",
                Outcome = "success",
                UserName = "synthetic-user",
                ProcessImage = "/usr/bin/synthetic-package-tool",
                SourceIp = "192.0.2.44",
                ServiceName = "synthetic-package.service",
                PackageName = "synthetic-package",
                User = new UserTelemetryConcept { Name = "synthetic-user", Id = "1001" },
                Process = new ProcessTelemetryConcept { Pid = "2201", Executable = "/usr/bin/synthetic-package-tool" },
                Network = new NetworkTelemetryConcept { SourceIp = "192.0.2.44", SourcePort = 4242, Protocol = "tcp" },
                Entities = Array.Empty<EventEntity>(),
                Labels = new Dictionary<string, string> { ["linux.event_family"] = "package_install" }
            },
            Raw = raw,
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw).Length,
                RedactionApplied = false,
                RedactedFields = Array.Empty<string>(),
                TruncationApplied = false,
                TruncatedFields = Array.Empty<string>()
            }
        };
        return envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };
    }

    private static EventEnvelope CreateEvent(
        string agentId,
        string hostname,
        Guid eventId,
        string channel,
        int windowsEventId,
        DateTimeOffset eventTime,
        string marker)
    {
        return new EventEnvelope
        {
            EventId = eventId,
            AgentId = agentId,
            Hostname = hostname,
            Source = EventSources.WindowsEventLog,
            Channel = channel,
            Provider = "IntegrationProvider",
            WindowsEventId = windowsEventId,
            RecordId = Random.Shared.NextInt64(1, long.MaxValue),
            EventTime = eventTime,
            HostTimezone = SyntheticPacificTimezone(),
            Severity = "information",
            Message = $"Integration event {marker}",
            Normalized = new NormalizedEventFields
            {
                Category = channel == "System" ? "system" : "application",
                Action = "observed",
                Entities = new[] { new EventEntity { Type = "host", Value = hostname, Role = "observed" } }
            },
            Raw = JsonSerializer.SerializeToElement(new { marker, agentId })
        };
    }

    private static async Task ClearServerRetentionOverridesAsync(string connectionString)
    {
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using var command = dataSource.CreateCommand("delete from server_config_settings where setting_key like 'retention.%';");
        await command.ExecuteNonQueryAsync(CancellationToken.None);
    }

    private static async Task AssertDatabaseStateAsync(NpgsqlDataSource dataSource, string agentId, Guid invalidBatchId)
    {
        await using (var eventCommand = dataSource.CreateCommand("select count(*) from events where agent_id = @agent_id;"))
        {
            eventCommand.Parameters.AddWithValue("agent_id", agentId);
            var eventCount = Convert.ToInt32(await eventCommand.ExecuteScalarAsync(CancellationToken.None));
            Assert.Equal(2, eventCount);
        }

        await using (var heartbeatCommand = dataSource.CreateCommand("select queue_depth from agent_heartbeats where agent_id = @agent_id order by heartbeat_time desc limit 1;"))
        {
            heartbeatCommand.Parameters.AddWithValue("agent_id", agentId);
            var queueDepth = Convert.ToInt32(await heartbeatCommand.ExecuteScalarAsync(CancellationToken.None));
            Assert.Equal(7, queueDepth);
        }

        await using (var errorCommand = dataSource.CreateCommand("select count(*) from ingestion_errors where agent_id = @agent_id and batch_id = @batch_id and error_code = 'validation_failed';"))
        {
            errorCommand.Parameters.AddWithValue("agent_id", agentId);
            errorCommand.Parameters.AddWithValue("batch_id", invalidBatchId);
            var errorCount = Convert.ToInt32(await errorCommand.ExecuteScalarAsync(CancellationToken.None));
            Assert.Equal(1, errorCount);
        }
    }

    private static IReadOnlyList<JsonElement> ParseServerSentEvents(string stream)
    {
        var events = new List<JsonElement>();
        var blocks = stream.Replace("\r\n", "\n", StringComparison.Ordinal).Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
        foreach (var block in blocks)
        {
            var dataLines = block.Split('\n')
                .Where(line => line.StartsWith("data: ", StringComparison.Ordinal))
                .Select(line => line[6..]);
            var data = string.Join("\n", dataLines).Trim();
            if (string.IsNullOrWhiteSpace(data))
            {
                continue;
            }

            events.Add(JsonDocument.Parse(data).RootElement.Clone());
        }

        return events;
    }

    private sealed class FakeSocAgentModelProvider(string answer) : ISocAgentModelProvider
    {
        public SocAgentModelProviderRequest? LastRequest { get; private set; }

        public Task<SocAgentModelProviderResult> CompleteAsync(SocAgentModelProviderRequest request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new SocAgentModelProviderResult(request.Status.Provider, request.Status.Model, answer));
        }
    }

    private sealed class SlowSocAgentModelProvider : ISocAgentModelProvider
    {
        public async Task<SocAgentModelProviderResult> CompleteAsync(SocAgentModelProviderRequest request, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            return new SocAgentModelProviderResult(request.Status.Provider, request.Status.Model, "This synthetic response should be cancelled before completion.");
        }
    }

    private static class JsonOptions
    {
        public static readonly JsonSerializerOptions Default = new(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower
        };
    }
}
