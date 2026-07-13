using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public sealed record EventSearchResponse
{
    [JsonPropertyName("events")]
    public IReadOnlyList<EventEnvelope> Events { get; init; } = Array.Empty<EventEnvelope>();

    [JsonPropertyName("page")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public EventSearchPageInfo? Page { get; init; }

    [JsonPropertyName("active_filters")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<EventSearchFilterSummary>? ActiveFilters { get; init; }

    [JsonPropertyName("result_scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResultScope { get; init; }

    [JsonPropertyName("redaction")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Redaction { get; init; }
}

public sealed record EventSearchPageInfo
{
    [JsonPropertyName("limit")]
    public int Limit { get; init; }

    [JsonPropertyName("returned")]
    public int Returned { get; init; }

    [JsonPropertyName("next_cursor")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NextCursor { get; init; }

    [JsonPropertyName("has_next")]
    public bool HasNext { get; init; }

    [JsonPropertyName("sort")]
    public string Sort { get; init; } = "event_time_desc";
}

public sealed record EventSearchFilterSummary
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; init; } = string.Empty;

    [JsonPropertyName("protected")]
    public bool Protected { get; init; }
}

public sealed record EventTimelineResponse
{
    [JsonPropertyName("buckets")]
    public IReadOnlyList<EventTimelineBucket> Buckets { get; init; } = Array.Empty<EventTimelineBucket>();

    [JsonPropertyName("bucket_seconds")]
    public int BucketSeconds { get; init; }

    [JsonPropertyName("utc_correlation")]
    public string UtcCorrelation { get; init; } = "event_time_utc";

    [JsonPropertyName("host_local_display")]
    public string HostLocalDisplay { get; init; } = "host_timezone metadata is displayed when present and never changes filtering";
}

public sealed record EventTimelineBucket
{
    [JsonPropertyName("start_utc")]
    public DateTimeOffset StartUtc { get; init; }

    [JsonPropertyName("end_utc")]
    public DateTimeOffset EndUtc { get; init; }

    [JsonPropertyName("count")]
    public long Count { get; init; }

    [JsonPropertyName("severity")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Severity { get; init; }

    [JsonPropertyName("source")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Source { get; init; }

    [JsonPropertyName("host_timezone_labels")]
    public IReadOnlyList<string> HostTimezoneLabels { get; init; } = Array.Empty<string>();
}

public sealed record SavedEventSearchRecord
{
    [JsonPropertyName("saved_search_id")]
    public Guid SavedSearchId { get; init; }

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("visibility")]
    public string Visibility { get; init; } = SavedEventSearchVisibility.Private;

    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("query")]
    public IReadOnlyDictionary<string, string> Query { get; init; } = new Dictionary<string, string>(StringComparer.Ordinal);

    [JsonPropertyName("columns")]
    public IReadOnlyList<string> Columns { get; init; } = Array.Empty<string>();

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; }

    [JsonPropertyName("updated_at")]
    public DateTimeOffset UpdatedAt { get; init; }

    [JsonPropertyName("created_by")]
    public string? CreatedBy { get; init; }
}

public static class SavedEventSearchVisibility
{
    public const string Private = "private";
    public const string Shared = "shared";

    public static bool IsValid(string? value) => value is Private or Shared;
}

public sealed record SavedEventSearchRequest
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("visibility")]
    public string Visibility { get; init; } = SavedEventSearchVisibility.Private;

    [JsonPropertyName("query")]
    public IReadOnlyDictionary<string, string> Query { get; init; } = new Dictionary<string, string>(StringComparer.Ordinal);

    [JsonPropertyName("columns")]
    public IReadOnlyList<string> Columns { get; init; } = Array.Empty<string>();

    [JsonPropertyName("expected_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? ExpectedVersion { get; init; }
}

public sealed record EventExportResponse
{
    [JsonPropertyName("status")]
    public string Status { get; init; } = "ready";

    [JsonPropertyName("format")]
    public string Format { get; init; } = "csv";

    [JsonPropertyName("rows")]
    public int Rows { get; init; }

    [JsonPropertyName("bounded_limit")]
    public int BoundedLimit { get; init; }

    [JsonPropertyName("audited")]
    public bool Audited { get; init; } = true;
}
