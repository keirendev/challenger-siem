using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V2;
using Microsoft.AspNetCore.Http;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed record NetworkActivityValidationError(string Field, string Message);

public sealed record NetworkActivityQuery
{
    public const int DefaultLimit = 100;
    public const int RestMaxLimit = 500;
    public const int McpMaxLimit = 100;
    public const int MaxGeoCandidates = 10_000;

    public DateTimeOffset? From { get; init; }
    public DateTimeOffset? To { get; init; }
    public string? Hostname { get; init; }
    public string? AgentId { get; init; }
    public string? RemoteIp { get; init; }
    public int? RemotePort { get; init; }
    public string? Protocol { get; init; }
    public string? ProcessImage { get; init; }
    public string? CountryCode { get; init; }
    public long? Asn { get; init; }
    public string? Direction { get; init; }
    public string? EvidenceMode { get; init; }
    public bool AttributedOnly { get; init; }
    public int Limit { get; init; } = DefaultLimit;
    public string? Cursor { get; init; }
    public IReadOnlyList<NetworkActivityValidationError> ValidationErrors { get; init; } = Array.Empty<NetworkActivityValidationError>();

    public static NetworkActivityQuery FromQuery(IQueryCollection values, int maxLimit = RestMaxLimit)
    {
        var errors = new List<NetworkActivityValidationError>();
        var from = Date(values, "from", errors);
        var to = Date(values, "to", errors);
        if (from.HasValue && to.HasValue && from > to) errors.Add(new("time", "from must be earlier than or equal to to."));
        var remoteIp = Text(values, "remote_ip", 64, errors);
        if (remoteIp is not null && !IPAddress.TryParse(remoteIp, out _)) errors.Add(new("remote_ip", "remote_ip must be a valid IPv4 or IPv6 address."));
        var protocol = Text(values, "protocol", 16, errors)?.ToLowerInvariant();
        if (protocol is not null && protocol is not ("tcp" or "udp")) errors.Add(new("protocol", "protocol must be tcp or udp."));
        var country = Text(values, "country_code", 2, errors)?.ToUpperInvariant();
        if (country is not null && (country.Length != 2 || country.Any(character => character is < 'A' or > 'Z')))
            errors.Add(new("country_code", "country_code must contain two ASCII letters."));
        var direction = Text(values, "direction", 16, errors)?.ToLowerInvariant();
        if (direction is not null && direction is not ("inbound" or "outbound" or "unknown"))
            errors.Add(new("direction", "direction must be inbound, outbound, or unknown."));
        var evidence = Text(values, "evidence_mode", 32, errors)?.ToLowerInvariant();
        if (evidence is not null && evidence is not ("kernel_flow" or "snapshot_diff"))
            errors.Add(new("evidence_mode", "evidence_mode must be kernel_flow or snapshot_diff."));
        var cursor = Text(values, "cursor", 512, errors, allowSymbols: true);
        if (cursor is not null && EventSearchCursor.TryDecode(cursor) is null)
            errors.Add(new("cursor", "cursor is invalid or expired."));

        return new()
        {
            From = from,
            To = to,
            Hostname = Text(values, "hostname", 128, errors),
            AgentId = Text(values, "agent_id", 128, errors),
            RemoteIp = remoteIp,
            RemotePort = Integer(values, "remote_port", 1, 65_535, errors),
            Protocol = protocol,
            ProcessImage = Text(values, "process_image", 260, errors, allowSymbols: true),
            CountryCode = country,
            Asn = Long(values, "asn", 1, uint.MaxValue, errors),
            Direction = direction,
            EvidenceMode = evidence,
            AttributedOnly = Boolean(values, "attributed_only", errors),
            Limit = Integer(values, "limit", 1, Math.Clamp(maxLimit, 1, RestMaxLimit), errors) ?? DefaultLimit,
            Cursor = cursor,
            ValidationErrors = errors
        };
    }

    public IReadOnlyList<EventSearchFilterSummary> ActiveFilters()
    {
        var result = new List<EventSearchFilterSummary>();
        void Add(string name, object? value, bool isProtected = false)
        {
            if (value is not null) result.Add(new() { Name = name, Value = Convert.ToString(value, CultureInfo.InvariantCulture)!, Protected = isProtected });
        }
        Add("from", From?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Add("to", To?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Add("hostname", Hostname);
        Add("agent_id", AgentId);
        Add("remote_ip", RemoteIp, true);
        Add("remote_port", RemotePort, true);
        Add("protocol", Protocol);
        Add("process_image", ProcessImage, true);
        Add("country_code", CountryCode);
        Add("asn", Asn);
        Add("direction", Direction);
        Add("evidence_mode", EvidenceMode);
        if (AttributedOnly) Add("attributed_only", true);
        return result;
    }

    private static DateTimeOffset? Date(IQueryCollection values, string key, List<NetworkActivityValidationError> errors)
    {
        var text = values[key].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)) return parsed.ToUniversalTime();
        errors.Add(new(key, $"{key} must be an RFC 3339 or UTC datetime value."));
        return null;
    }

    private static int? Integer(IQueryCollection values, string key, int minimum, int maximum, List<NetworkActivityValidationError> errors)
    {
        var text = values[key].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= minimum && parsed <= maximum) return parsed;
        errors.Add(new(key, $"{key} must be between {minimum} and {maximum}."));
        return null;
    }

    private static long? Long(IQueryCollection values, string key, long minimum, long maximum, List<NetworkActivityValidationError> errors)
    {
        var text = values[key].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= minimum && parsed <= maximum) return parsed;
        errors.Add(new(key, $"{key} must be between {minimum} and {maximum}."));
        return null;
    }

    private static bool Boolean(IQueryCollection values, string key, List<NetworkActivityValidationError> errors)
    {
        var text = values[key].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (bool.TryParse(text, out var parsed)) return parsed;
        errors.Add(new(key, $"{key} must be true or false."));
        return false;
    }

    private static string? Text(IQueryCollection values, string key, int maximum, List<NetworkActivityValidationError> errors, bool allowSymbols = false)
    {
        var value = values[key].FirstOrDefault()?.Trim();
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (value.Length > maximum || value.Any(char.IsControl)
            || !allowSymbols && value.Any(character => !(char.IsLetterOrDigit(character) || character is '-' or '_' or '.' or ':' or '/')))
        {
            errors.Add(new(key, $"{key} must be {maximum} characters or fewer and contain supported characters only."));
            return null;
        }
        return value;
    }
}

public sealed class NetworkActivityRepository(
    NpgsqlDataSource dataSource,
    IpGeolocationService geolocation,
    TimeProvider timeProvider)
{
    private const string SnapshotSource = LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff;
    private const string KernelSource = LinuxTelemetrySourceIds.NetworkFlowSummary;

    public async Task<NetworkActivityResponse> SearchAsync(
        NetworkActivityQuery query,
        bool allowGeolocationLookup,
        CancellationToken cancellationToken)
    {
        var geoFilterRequested = query.CountryCode is not null || query.Asn.HasValue;
        IReadOnlyList<string> geoFilterIps = Array.Empty<string>();
        if (geoFilterRequested)
        {
            geoFilterIps = allowGeolocationLookup
                ? await geolocation.SearchCachedIpsAsync(null, query.CountryCode, query.Asn, NetworkActivityQuery.MaxGeoCandidates, cancellationToken)
                : await geolocation.SearchCachedIpsReadOnlyAsync(null, query.CountryCode, query.Asn, NetworkActivityQuery.MaxGeoCandidates, cancellationToken);
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var where = new List<string> { "source_id in (@snapshot_source,@kernel_source)" };
        command.Parameters.AddWithValue("snapshot_source", SnapshotSource);
        command.Parameters.AddWithValue("kernel_source", KernelSource);
        Add(where, command, query, geoFilterRequested, geoFilterIps);
        command.Parameters.AddWithValue("limit", Math.Clamp(query.Limit, 1, NetworkActivityQuery.RestMaxLimit) + 1);
        command.CommandText = $"""
            select id,event_id,agent_id,hostname,source_id,event_code,event_time,
                   normalized_json,raw_json,process_image,process_command_line,source_ip,destination_ip
            from events
            where {string.Join(" and ", where)}
            order by event_time desc,id desc
            limit @limit;
            """;

        var candidates = new List<ActivityCandidate>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken)) candidates.Add(Read(reader));
        }

        var hasNext = candidates.Count > query.Limit;
        if (hasNext) candidates.RemoveAt(candidates.Count - 1);
        var remoteIps = candidates.Select(item => item.Activity.RemoteIp).Where(item => item is not null).Cast<string>().Distinct(StringComparer.Ordinal).ToArray();
        var cached = allowGeolocationLookup
            ? await geolocation.GetCachedAsync(remoteIps, cancellationToken)
            : await geolocation.GetCachedReadOnlyAsync(remoteIps, cancellationToken);
        var activities = candidates.Select(item => ApplyGeolocation(item.Activity, item.Activity.RemoteIp is null ? null : cached.GetValueOrDefault(item.Activity.RemoteIp))).ToArray();
        var last = candidates.LastOrDefault();
        return new()
        {
            GeneratedAtUtc = timeProvider.GetUtcNow(),
            Activities = activities,
            Page = new()
            {
                Limit = query.Limit,
                Returned = activities.Length,
                HasNext = hasNext,
                NextCursor = hasNext && last is not null ? EventSearchCursor.Encode(last.Activity.EventTimeUtc, last.RowId) : null
            },
            ActiveFilters = query.ActiveFilters(),
            GeolocationMode = allowGeolocationLookup ? "on_demand_cache" : "cache_only_no_writes",
            Limitations =
            [
                "Kernel flow packet counts are cgroup SKB observations and byte counts are SKB lengths; offload and segmentation mean they are not wire-accurate counters.",
                "Snapshot-diff evidence can miss short-lived sockets and does not prove packet direction or volume.",
                "Process attribution is point-in-time evidence and may be partial or ambiguous; use attribution_confidence and source health.",
                "IP geolocation is approximate cached provider metadata and is not proof of physical location or actor identity."
            ]
        };
    }

    private static void Add(
        List<string> where,
        NpgsqlCommand command,
        NetworkActivityQuery query,
        bool geoFilterRequested,
        IReadOnlyList<string> geoFilterIps)
    {
        if (query.From.HasValue) { where.Add("event_time >= @from"); command.Parameters.AddWithValue("from", query.From.Value.ToUniversalTime()); }
        if (query.To.HasValue) { where.Add("event_time <= @to"); command.Parameters.AddWithValue("to", query.To.Value.ToUniversalTime()); }
        if (query.Hostname is not null) { where.Add("hostname ilike @hostname escape '\\'"); command.Parameters.AddWithValue("hostname", $"%{EscapeLike(query.Hostname)}%"); }
        if (query.AgentId is not null) { where.Add("agent_id ilike @agent_id escape '\\'"); command.Parameters.AddWithValue("agent_id", $"%{EscapeLike(query.AgentId)}%"); }
        if (query.RemoteIp is not null) { where.Add("coalesce(normalized_json #>> '{network,remote_ip}',destination_ip) = @remote_ip"); command.Parameters.AddWithValue("remote_ip", query.RemoteIp); }
        if (query.RemotePort.HasValue) { where.Add("coalesce(normalized_json #>> '{network,remote_port}',normalized_json->>'destination_port',raw_json->>'remote_port') = @remote_port"); command.Parameters.AddWithValue("remote_port", query.RemotePort.Value.ToString(CultureInfo.InvariantCulture)); }
        if (query.Protocol is not null) { where.Add("lower(coalesce(normalized_json #>> '{network,protocol}',normalized_json->>'protocol',raw_json->>'protocol','')) = @protocol"); command.Parameters.AddWithValue("protocol", query.Protocol); }
        if (query.ProcessImage is not null) { where.Add("coalesce(process_image,'') ilike @process_image escape '\\'"); command.Parameters.AddWithValue("process_image", $"%{EscapeLike(query.ProcessImage)}%"); }
        if (query.Direction is not null) { where.Add("coalesce(normalized_json #>> '{network,direction}',raw_json->>'direction','unknown') = @direction"); command.Parameters.AddWithValue("direction", query.Direction); }
        if (query.EvidenceMode is not null) { where.Add("coalesce(normalized_json #>> '{network,evidence_mode}',raw_json->>'evidence_mode','unknown') = @evidence_mode"); command.Parameters.AddWithValue("evidence_mode", query.EvidenceMode); }
        if (query.AttributedOnly) where.Add("coalesce(process_image,normalized_json->>'process_id',normalized_json #>> '{process,pid}',raw_json->>'owner_process_id',raw_json->>'process_id') is not null");
        if (geoFilterRequested)
        {
            if (geoFilterIps.Count == 0) where.Add("false");
            else { where.Add("coalesce(normalized_json #>> '{network,remote_ip}',destination_ip) = any(@geo_ips)"); command.Parameters.AddWithValue("geo_ips", geoFilterIps.ToArray()); }
        }
        var cursor = EventSearchCursor.TryDecode(query.Cursor);
        if (cursor is not null)
        {
            where.Add("(event_time,id) < (@cursor_time,@cursor_id)");
            command.Parameters.AddWithValue("cursor_time", cursor.EventTime.ToUniversalTime());
            command.Parameters.AddWithValue("cursor_id", cursor.RowId);
        }
    }

    private static ActivityCandidate Read(NpgsqlDataReader reader)
    {
        var rowId = reader.GetInt64(reader.GetOrdinal("id"));
        var eventId = reader.GetGuid(reader.GetOrdinal("event_id"));
        var agentId = reader.GetString(reader.GetOrdinal("agent_id"));
        var eventTime = ReadDate(reader, "event_time");
        using var normalized = ReadDocument(reader, "normalized_json");
        using var raw = ReadDocument(reader, "raw_json");
        var normal = normalized?.RootElement;
        var rawRoot = raw?.RootElement;
        var localIp = First(Path(normal, "network", "local_ip"), Path(normal, "source_ip"), Path(rawRoot, "local_address"), Path(rawRoot, "local_ip"));
        var remoteIp = First(Path(normal, "network", "remote_ip"), Path(normal, "destination_ip"), Path(rawRoot, "remote_address"), Path(rawRoot, "remote_ip"));
        var processImage = ReadNullable(reader, "process_image") ?? First(Path(normal, "process", "executable"), Path(rawRoot, "owner_executable"), Path(rawRoot, "process_image"));
        var processCommand = ReadNullable(reader, "process_command_line") ?? First(Path(normal, "process", "command_line"), Path(rawRoot, "owner_command_line"), Path(rawRoot, "owner_command"));
        var activity = new NetworkActivityRecord
        {
            AgentId = agentId,
            EventId = eventId,
            EventCitation = $"event:{agentId}/{eventId}",
            EventTimeUtc = eventTime,
            Hostname = reader.GetString(reader.GetOrdinal("hostname")),
            SourceId = reader.GetString(reader.GetOrdinal("source_id")),
            EventCode = ReadNullable(reader, "event_code"),
            EvidenceMode = First(Path(normal, "network", "evidence_mode"), Path(rawRoot, "evidence_mode")) ?? "unknown",
            Direction = First(Path(normal, "network", "direction"), Path(rawRoot, "direction")) ?? "unknown",
            LocalIp = localIp,
            LocalPort = FirstInt(Path(normal, "network", "local_port"), Path(normal, "source_port"), Path(rawRoot, "local_port")),
            RemoteIp = remoteIp,
            RemotePort = FirstInt(Path(normal, "network", "remote_port"), Path(normal, "destination_port"), Path(rawRoot, "remote_port")),
            Protocol = First(Path(normal, "network", "protocol"), Path(normal, "protocol"), Path(rawRoot, "protocol")),
            ProcessId = FirstInt(Path(normal, "process_id"), Path(normal, "process", "pid"), Path(rawRoot, "owner_process_id"), Path(rawRoot, "process_id")),
            ProcessImage = processImage,
            ProcessCommandLine = processCommand,
            UserId = First(Path(normal, "user", "id"), Path(rawRoot, "owner_user_id"), Path(rawRoot, "user_id")),
            AttributionConfidence = First(Path(normal, "network", "attribution_confidence"), Path(rawRoot, "owner_confidence"), Path(rawRoot, "attribution_confidence")) ?? (processImage is null ? "unattributed" : "snapshot_owner"),
            FirstSeenUtc = FirstDate(Path(normal, "network", "interval_started_at"), Path(rawRoot, "first_seen_utc")) ?? eventTime,
            LastSeenUtc = FirstDate(Path(normal, "network", "interval_ended_at"), Path(rawRoot, "last_seen_utc")) ?? eventTime,
            PacketCountDelta = FirstLong(Path(normal, "network", "packet_count_delta"), Path(rawRoot, "packet_count_delta")),
            ByteCountDelta = FirstLong(Path(normal, "network", "byte_count_delta"), Path(rawRoot, "byte_count_delta")),
            TcpFlags = StringArray(normal, rawRoot, "tcp_flags")
        };
        return new(rowId, activity);
    }

    private static NetworkActivityRecord ApplyGeolocation(NetworkActivityRecord activity, IpGeolocationRecord? geo)
    {
        if (geo is null)
        {
            return activity with
            {
                GeolocationStatus = activity.RemoteIp is not null && !IpAddressScopeClassifier.IsPubliclyRoutable(activity.RemoteIp) ? "unmapped" : "pending"
            };
        }
        return activity with
        {
            GeolocationStatus = geo.Status,
            Country = geo.Country,
            CountryCode = geo.CountryCode,
            City = geo.City,
            Region = geo.Region,
            Continent = geo.Continent,
            Asn = geo.Asn,
            Organization = geo.Organization,
            GeolocationFetchedAtUtc = geo.FetchedAtUtc
        };
    }

    private static JsonDocument? ReadDocument(NpgsqlDataReader reader, string column)
    {
        var ordinal = reader.GetOrdinal(column);
        return reader.IsDBNull(ordinal) ? null : JsonDocument.Parse(reader.GetString(ordinal));
    }

    private static DateTimeOffset ReadDate(NpgsqlDataReader reader, string column)
    {
        var value = reader.GetFieldValue<DateTime>(reader.GetOrdinal(column));
        return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
    }

    private static string? ReadNullable(NpgsqlDataReader reader, string column)
    {
        var ordinal = reader.GetOrdinal(column);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static string? Path(JsonElement? root, params string[] path)
    {
        if (root is not { ValueKind: JsonValueKind.Object } current) return null;
        foreach (var part in path)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(part, out current)) return null;
        }
        return current.ValueKind switch
        {
            JsonValueKind.String => current.GetString(),
            JsonValueKind.Number => current.GetRawText(),
            _ => null
        };
    }

    private static string? First(params string?[] values) => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
    private static int? FirstInt(params string?[] values) => int.TryParse(First(values), NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;
    private static long? FirstLong(params string?[] values) => long.TryParse(First(values), NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;
    private static DateTimeOffset? FirstDate(params string?[] values) => DateTimeOffset.TryParse(First(values), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value) ? value : null;

    private static IReadOnlyList<string> StringArray(JsonElement? normalized, JsonElement? raw, string name)
    {
        if (normalized is { ValueKind: JsonValueKind.Object } normal
            && normal.TryGetProperty("network", out var network)
            && network.ValueKind == JsonValueKind.Object
            && network.TryGetProperty(name, out var normalArray)
            && normalArray.ValueKind == JsonValueKind.Array)
            return normalArray.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()!).Take(16).ToArray();
        if (raw is { ValueKind: JsonValueKind.Object } rawObject
            && rawObject.TryGetProperty(name, out var rawArray)
            && rawArray.ValueKind == JsonValueKind.Array)
            return rawArray.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()!).Take(16).ToArray();
        return Array.Empty<string>();
    }

    private static string EscapeLike(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);

    private sealed record ActivityCandidate(long RowId, NetworkActivityRecord Activity);
}
