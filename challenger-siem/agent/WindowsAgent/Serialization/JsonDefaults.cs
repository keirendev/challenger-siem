using System.Text.Json;

namespace Challenger.Siem.WindowsAgent.Serialization;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false
    };

    public static JsonElement ToJsonElement<T>(T value)
    {
        var json = JsonSerializer.Serialize(value, Options);
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }
}
