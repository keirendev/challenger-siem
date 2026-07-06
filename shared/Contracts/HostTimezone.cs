using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public sealed record HostTimezoneMetadata
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = string.Empty;

    [JsonPropertyName("standard_name")]
    public string? StandardName { get; init; }

    [JsonPropertyName("daylight_name")]
    public string? DaylightName { get; init; }

    [JsonPropertyName("base_utc_offset_minutes")]
    public int? BaseUtcOffsetMinutes { get; init; }

    [JsonPropertyName("utc_offset_minutes")]
    public int? UtcOffsetMinutes { get; init; }

    [JsonPropertyName("is_daylight_saving_time")]
    public bool? IsDaylightSavingTime { get; init; }
}
