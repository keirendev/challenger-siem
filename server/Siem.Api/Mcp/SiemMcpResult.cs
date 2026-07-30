using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Challenger.Siem.Api.Mcp;

public sealed record SiemMcpCitation
{
    [JsonPropertyName("record_type")]
    public required string RecordType { get; init; }

    [JsonPropertyName("record_id")]
    public required string RecordId { get; init; }
}

public sealed record SiemMcpResult<T>
{
    [JsonPropertyName("schema_version")]
    public string SchemaVersion { get; init; } = "challenger-siem.mcp.v1";

    [JsonPropertyName("generated_at")]
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("kind")]
    public required string Kind { get; init; }

    [JsonPropertyName("data_classification")]
    public string DataClassification { get; init; } = "siem_sensitive";

    [JsonPropertyName("redaction")]
    public required string Redaction { get; init; }

    [JsonPropertyName("untrusted_telemetry")]
    public bool UntrustedTelemetry { get; init; } = true;

    [JsonPropertyName("read_only")]
    public bool ReadOnly { get; init; } = true;

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("row_count")]
    public int RowCount { get; init; }

    [JsonPropertyName("data")]
    public required T Data { get; init; }

    [JsonPropertyName("citations")]
    public IReadOnlyList<SiemMcpCitation> Citations { get; init; } = Array.Empty<SiemMcpCitation>();

    [JsonPropertyName("warnings")]
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}

public static class SiemMcpResults
{
    public static SiemMcpResult<T> Create<T>(
        string kind,
        T data,
        int rowCount,
        string redaction,
        bool truncated = false,
        IReadOnlyList<SiemMcpCitation>? citations = null,
        IReadOnlyList<string>? warnings = null,
        string dataClassification = "siem_sensitive",
        bool omitRawFields = false)
    {
        var filtered = SiemMcpContentPolicy.Apply(data, omitRawFields);
        var filteredCitations = SiemMcpContentPolicy.Apply(
            citations ?? Array.Empty<SiemMcpCitation>());
        var filteredWarnings = SiemMcpContentPolicy.Apply(
            warnings ?? Array.Empty<string>());
        var policyLabel = filtered.RawOmitted
            ? "mcp_raw_omitted_secret_shape_filter"
            : "mcp_secret_shape_filter";
        return new()
        {
            Kind = kind,
            Data = filtered.Value,
            RowCount = Math.Max(0, rowCount),
            Redaction = $"{redaction};{policyLabel}",
            Truncated = truncated,
            Citations = filteredCitations.Value,
            Warnings = filteredWarnings.Value,
            DataClassification = dataClassification
        };
    }
}

public static class SiemMcpJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        TypeInfoResolver = new DefaultJsonTypeInfoResolver()
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
}
