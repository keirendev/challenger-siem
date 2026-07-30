using System.Text.Json;

namespace Challenger.Siem.Api.Mcp;

public sealed record SiemMcpContentPolicyResult<T>(T Value, bool RedactionApplied, bool RawOmitted);

/// <summary>
/// Applies a final fail-closed, best-effort secret-shape filter to every structured MCP result.
/// This boundary is intentionally independent of endpoint-agent sanitation because MCP must not
/// trust a registered endpoint, stored analyst text, or a future repository projection to have
/// removed credentials before content reaches an external agent.
/// </summary>
public static class SiemMcpContentPolicy
{
    private const string Redacted = "<redacted>";

    public static SiemMcpContentPolicyResult<T> Apply<T>(T value, bool omitRawFields = false)
    {
        ArgumentNullException.ThrowIfNull(value);

        var source = JsonSerializer.SerializeToElement(value, SiemMcpJson.Options);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            var state = new PolicyState();
            Write(source, writer, propertyName: null, omitRawFields, state);
            writer.Flush();

            var filtered = JsonSerializer.Deserialize<T>(buffer.ToArray(), SiemMcpJson.Options)
                ?? throw new InvalidOperationException("MCP content policy produced an empty structured result.");
            return new SiemMcpContentPolicyResult<T>(filtered, state.RedactionApplied, state.RawOmitted);
        }
    }

    private static void Write(
        JsonElement element,
        Utf8JsonWriter writer,
        string? propertyName,
        bool omitRawFields,
        PolicyState state)
    {
        if (propertyName is not null && SiemMcpInventoryPolicy.IsSensitiveKey(propertyName))
        {
            if (element.ValueKind == JsonValueKind.Null)
            {
                writer.WriteNullValue();
            }
            else
            {
                writer.WriteStringValue(Redacted);
                state.RedactionApplied = true;
            }
            return;
        }

        if (omitRawFields && string.Equals(propertyName, "raw", StringComparison.OrdinalIgnoreCase))
        {
            writer.WriteStartObject();
            writer.WriteEndObject();
            state.RawOmitted = true;
            return;
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    Write(property.Value, writer, property.Name, omitRawFields, state);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    Write(item, writer, propertyName: null, omitRawFields, state);
                }
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                var original = element.GetString() ?? string.Empty;
                var filtered = SiemMcpInventoryPolicy.RedactText(original);
                writer.WriteStringValue(filtered);
                state.RedactionApplied |= !string.Equals(original, filtered, StringComparison.Ordinal);
                break;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                element.WriteTo(writer);
                break;
            default:
                writer.WriteNullValue();
                state.RedactionApplied = true;
                break;
        }
    }

    private sealed class PolicyState
    {
        public bool RedactionApplied { get; set; }
        public bool RawOmitted { get; set; }
    }
}
