using Microsoft.AspNetCore.Http;

namespace Challenger.Siem.Api.Database;

public sealed record EventSearchQuery(
    string? Hostname,
    string? AgentId,
    string? Channel,
    int? WindowsEventId,
    DateTimeOffset? From,
    DateTimeOffset? To,
    string? Keyword,
    int Limit)
{
    public static EventSearchQuery FromQuery(IQueryCollection query)
    {
        return new EventSearchQuery(
            ReadString(query, "hostname"),
            ReadString(query, "agent_id"),
            ReadString(query, "channel"),
            ReadInt(query, "windows_event_id"),
            ReadDateTimeOffset(query, "from"),
            ReadDateTimeOffset(query, "to"),
            ReadString(query, "keyword"),
            ReadInt(query, "limit") ?? 100);
    }

    private static string? ReadString(IQueryCollection query, string key)
    {
        return query.TryGetValue(key, out var values) ? values.FirstOrDefault() : null;
    }

    private static int? ReadInt(IQueryCollection query, string key)
    {
        var value = ReadString(query, key);
        return int.TryParse(value, out var parsed) ? parsed : null;
    }

    private static DateTimeOffset? ReadDateTimeOffset(IQueryCollection query, string key)
    {
        var value = ReadString(query, key);
        return DateTimeOffset.TryParse(value, out var parsed) ? parsed.ToUniversalTime() : null;
    }
}
