using System.Text.Json;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class EventSearchTimelineTests
{
    [Fact]
    public void NestedLegacySearchFallbackKeepsDenormalizedPredicatesIndexable()
    {
        var implementation = File.ReadAllText(RepositoryFile("server", "Siem.Api", "Database", "EventRepository.cs"));

        Assert.Contains("AddFallbackTextFilter(where, command, \"process_command_line\"", implementation, StringComparison.Ordinal);
        Assert.Contains("AddFallbackTextFilter(where, command, \"file_path\"", implementation, StringComparison.Ordinal);
        Assert.Contains("AddFallbackTextFilter(where, command, \"source_ip\"", implementation, StringComparison.Ordinal);
        Assert.Contains("indexedExpression} is null and {legacyFallbackExpression}", implementation, StringComparison.Ordinal);
        Assert.DoesNotContain("coalesce(process_command_line, normalized_json", implementation, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("coalesce(file_path, normalized_json", implementation, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("coalesce(source_ip, normalized_json", implementation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EventSearchQueryValidatesBoundsAndStructuredFilters()
    {
        var query = EventSearchQuery.FromQuery(new QueryCollection(new Dictionary<string, StringValues>
        {
            ["platform"] = "linux",
            ["source"] = "linux_journal",
            ["provider"] = "sshd",
            ["facility"] = "authpriv",
            ["unit"] = "sshd.service",
            ["event_code"] = "ssh.login.failure",
            ["severity"] = "warning",
            ["outcome"] = "failure",
            ["entity_type"] = "user",
            ["entity_value"] = "synthetic-user",
            ["limit"] = "9999",
            ["bucket_seconds"] = "15",
            ["columns"] = "event_time,host,unsupported"
        }));

        Assert.Equal("linux", query.Platform);
        Assert.Equal("linux_journal", query.Source);
        Assert.Equal("sshd", query.Provider);
        Assert.Equal(EventSearchQuery.MaxLimit, query.Limit);
        var exportQuery = EventSearchQuery.FromQuery(new QueryCollection(new Dictionary<string, StringValues> { ["limit"] = "5000" }), EventSearchQuery.MaxExportLimit);
        Assert.Equal(EventSearchQuery.MaxExportLimit, exportQuery.Limit);
        Assert.Equal(60, query.BucketSeconds);
        Assert.Contains(query.ValidationErrors, item => item.Field == "limit");
        Assert.Contains(query.ValidationErrors, item => item.Field == "bucket_seconds");
        Assert.Contains(query.ValidationErrors, item => item.Field == "columns");
        Assert.DoesNotContain("unsupported", query.Columns);
    }

    [Fact]
    public void ViewerRoleRemovesSensitiveFiltersBeforeRepositoryUse()
    {
        var query = EventSearchQuery.Empty with
        {
            Keyword = "secret-shaped synthetic term",
            UserName = "synthetic-user",
            ProcessImage = "C:/Tools/demo.exe",
            SourceIp = "192.0.2.10",
            EntityType = "user",
            EntityValue = "synthetic-user",
            AgentId = "demo-agent"
        };

        var roleQuery = query.ForRole("viewer");
        Assert.Equal("demo-agent", roleQuery.AgentId);
        Assert.Null(roleQuery.Keyword);
        Assert.Null(roleQuery.UserName);
        Assert.Null(roleQuery.ProcessImage);
        Assert.Null(roleQuery.SourceIp);
        Assert.Null(roleQuery.EntityType);
        Assert.Null(roleQuery.EntityValue);
    }

    [Fact]
    public void SavedSearchRolePolicyDoesNotDiscloseProtectedFilterValues()
    {
        var saved = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["agent_id"] = "synthetic-agent",
            ["PROCESS_COMMAND_LINE"] = "/usr/bin/synthetic --private-value",
            ["source_ip"] = "192.0.2.10",
            ["destination_port"] = "443",
            ["file_path"] = "/opt/synthetic/private.conf",
            ["entity_type"] = "user",
            ["entity_value"] = "synthetic-private-user"
        };

        var viewer = EventSearchQuery.SavedQueryForRole(saved, "viewer");
        Assert.Equal("synthetic-agent", viewer["agent_id"]);
        Assert.DoesNotContain(viewer, item => item.Key.Equals("process_command_line", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("source_ip", viewer.Keys);
        Assert.DoesNotContain("destination_port", viewer.Keys);
        Assert.DoesNotContain("file_path", viewer.Keys);
        Assert.DoesNotContain("entity_type", viewer.Keys);
        Assert.DoesNotContain("entity_value", viewer.Keys);

        var analyst = EventSearchQuery.SavedQueryForRole(saved, "analyst");
        Assert.Equal(saved.Count, analyst.Count);
        Assert.Equal("/usr/bin/synthetic --private-value", analyst["process_command_line"]);
    }

    [Fact]
    public void CursorRoundTripIsBoundedAndTamperDetecting()
    {
        var now = DateTimeOffset.UtcNow;
        var encoded = EventSearchCursor.Encode(now, 42);
        var decoded = EventSearchCursor.TryDecode(encoded);
        Assert.NotNull(decoded);
        Assert.Equal(42, decoded!.RowId);
        Assert.Equal(now.ToUniversalTime().ToUnixTimeSeconds(), decoded.EventTime.ToUnixTimeSeconds());
        Assert.Null(EventSearchCursor.TryDecode(encoded + "tampered"));
    }

    [Fact]
    public void AdditiveEventSearchContractsSerializeWithoutBreakingEventsArray()
    {
        var response = new EventSearchResponse
        {
            Events = Array.Empty<EventEnvelope>(),
            Page = new EventSearchPageInfo { Limit = 100, Returned = 0, HasNext = false },
            ActiveFilters = new[] { new EventSearchFilterSummary { Name = "platform", Value = "linux", Protected = false } },
            ResultScope = "1 active filters over all retained UTC event time; newest first; limit 100; role analyst.",
            Redaction = "raw_omitted_sensitive_fields_redacted"
        };

        var json = JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.TryGetProperty("events", out _));
        Assert.True(document.RootElement.TryGetProperty("page", out var page));
        Assert.False(page.GetProperty("has_next").GetBoolean());
        Assert.Equal("linux", document.RootElement.GetProperty("active_filters")[0].GetProperty("value").GetString());
    }

    private static string RepositoryFile(params string[] parts)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(new[] { current.FullName }.Concat(parts).ToArray());
            if (File.Exists(candidate)) return candidate;
            current = current.Parent;
        }
        throw new FileNotFoundException($"Could not locate repository file: {string.Join('/', parts)}");
    }

    [Fact]
    public void SearchSavedQueryMigrationAddsTablesAndIndexSupportedPredicates()
    {
        var sql = File.ReadAllText(RepositoryPath("server", "Siem.Api", "Database", "009_search_saved_queries.sql"));
        Assert.Contains("create table if not exists saved_event_searches", sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("idx_events_provider_time", sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("idx_events_facility_time", sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("idx_events_unit_time", sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("idx_events_severity_time", sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("idx_events_outcome_time", sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("idx_alert_evidence_agent_event", sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("idx_alerts_rule_id", sql, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EventSearchRazorKeepsAccessibilityAndConfirmationSurfaces()
    {
        var markup = File.ReadAllText(RepositoryPath("server", "Siem.Api", "Pages", "Events", "Index.cshtml"));
        Assert.Contains("aria-label=\"Event search filters\"", markup, StringComparison.Ordinal);
        Assert.Contains("Timeline buckets", markup, StringComparison.Ordinal);
        Assert.Contains("Saved searches", markup, StringComparison.Ordinal);
        Assert.Contains("Type EXPORT to confirm", markup, StringComparison.Ordinal);
        Assert.Contains("Next cursor", markup, StringComparison.Ordinal);
    }

    [Fact]
    public void EventDetailRazorFallsBackToPortableNestedTelemetry()
    {
        var markup = File.ReadAllText(RepositoryPath("server", "Siem.Api", "Pages", "Events", "Detail.cshtml"));
        Assert.Contains("Process?.Pid", markup, StringComparison.Ordinal);
        Assert.Contains("Process?.ParentPid", markup, StringComparison.Ordinal);
        Assert.Contains("Process?.Executable", markup, StringComparison.Ordinal);
        Assert.Contains("Process?.CommandLine", markup, StringComparison.Ordinal);
        Assert.Contains("Network?.SourceIp", markup, StringComparison.Ordinal);
        Assert.Contains("Network?.DestinationPort", markup, StringComparison.Ordinal);
        Assert.Contains("File?.Path", markup, StringComparison.Ordinal);
        Assert.Contains("File?.Sha256", markup, StringComparison.Ordinal);
    }

    private static string RepositoryPath(params string[] parts)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln"))) current = current.Parent;
        return Path.Combine(new[] { current?.FullName ?? throw new InvalidOperationException("Repository root not found.") }.Concat(parts).ToArray());
    }
}
