using System.Globalization;
using System.Text;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V2;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed record NetworkGeographyValidationError(string Field, string Message);

public sealed record NetworkGeographyQuery
{
    public const int DefaultLimit = 500;
    public const int MaxLimit = 2000;
    public const int MaxCandidates = 10000;

    public DateTimeOffset? From { get; init; }
    public DateTimeOffset? To { get; init; }
    public string? Query { get; init; }
    public string? Hostname { get; init; }
    public string? AgentId { get; init; }
    public string? DestinationIp { get; init; }
    public int? DestinationPort { get; init; }
    public string? Protocol { get; init; }
    public string? ProcessImage { get; init; }
    public string? CountryCode { get; init; }
    public long? Asn { get; init; }
    public int Limit { get; init; } = DefaultLimit;
    public IReadOnlyList<NetworkGeographyValidationError> ValidationErrors { get; init; } = Array.Empty<NetworkGeographyValidationError>();

    public static NetworkGeographyQuery FromQuery(IQueryCollection values)
    {
        var errors = new List<NetworkGeographyValidationError>();
        var from = Date(values, "from", errors);
        var to = Date(values, "to", errors);
        if (from.HasValue && to.HasValue && from > to) errors.Add(new("time", "from must be earlier than or equal to to."));
        var port = Integer(values, "destination_port", 1, 65535, errors);
        var limit = Integer(values, "limit", 1, MaxLimit, errors) ?? DefaultLimit;
        var asn = Long(values, "asn", 1, uint.MaxValue, errors);
        var protocol = Text(values, "protocol", 16, errors)?.ToLowerInvariant();
        if (protocol is not null && protocol is not ("tcp" or "udp")) errors.Add(new("protocol", "protocol must be tcp or udp."));
        var country = Text(values, "country_code", 2, errors)?.ToUpperInvariant();
        if (country is not null && (country.Length != 2 || country.Any(character => character is < 'A' or > 'Z')))
            errors.Add(new("country_code", "country_code must contain two ASCII letters."));
        var destinationIp = Text(values, "destination_ip", 64, errors);
        if (destinationIp is not null && !System.Net.IPAddress.TryParse(destinationIp, out _))
            errors.Add(new("destination_ip", "destination_ip must be a valid IPv4 or IPv6 address."));

        return new()
        {
            From = from,
            To = to,
            Query = Text(values, "q", 160, errors, allowSymbols: true),
            Hostname = Text(values, "hostname", 128, errors),
            AgentId = Text(values, "agent_id", 128, errors),
            DestinationIp = destinationIp,
            DestinationPort = port,
            Protocol = protocol,
            ProcessImage = Text(values, "process_image", 260, errors, allowSymbols: true),
            CountryCode = country,
            Asn = asn,
            Limit = limit,
            ValidationErrors = errors
        };
    }

    public IReadOnlyList<EventSearchFilterSummary> ActiveFilters()
    {
        var filters = new List<EventSearchFilterSummary>();
        void Add(string name, object? value, bool sensitive = false)
        {
            if (value is not null) filters.Add(new() { Name = name, Value = Convert.ToString(value, CultureInfo.InvariantCulture)!, Protected = sensitive });
        }
        Add("from", From?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Add("to", To?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Add("q", Query, true);
        Add("hostname", Hostname);
        Add("agent_id", AgentId);
        Add("destination_ip", DestinationIp, true);
        Add("destination_port", DestinationPort, true);
        Add("protocol", Protocol);
        Add("process_image", ProcessImage, true);
        Add("country_code", CountryCode);
        Add("asn", Asn);
        return filters;
    }

    private static DateTimeOffset? Date(IQueryCollection values, string key, List<NetworkGeographyValidationError> errors)
    {
        var text = values[key].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)) return parsed.ToUniversalTime();
        errors.Add(new(key, $"{key} must be an RFC 3339 or UTC datetime value."));
        return null;
    }

    private static int? Integer(IQueryCollection values, string key, int minimum, int maximum, List<NetworkGeographyValidationError> errors)
    {
        var text = values[key].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= minimum && parsed <= maximum) return parsed;
        errors.Add(new(key, $"{key} must be between {minimum} and {maximum}."));
        return null;
    }

    private static long? Long(IQueryCollection values, string key, long minimum, long maximum, List<NetworkGeographyValidationError> errors)
    {
        var text = values[key].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= minimum && parsed <= maximum) return parsed;
        errors.Add(new(key, $"{key} must be between {minimum} and {maximum}."));
        return null;
    }

    private static string? Text(IQueryCollection values, string key, int maximum, List<NetworkGeographyValidationError> errors, bool allowSymbols = false)
    {
        var value = values[key].FirstOrDefault()?.Trim();
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (value.Length > maximum || value.Any(char.IsControl) || !allowSymbols && value.Any(character => !(char.IsLetterOrDigit(character) || character is '-' or '_' or '.' or ':' or '/')))
        {
            errors.Add(new(key, $"{key} must be {maximum} characters or fewer and contain supported characters only."));
            return null;
        }
        return value;
    }
}

public sealed class NetworkGeographyRepository(
    NpgsqlDataSource dataSource,
    IpGeolocationService geolocation,
    IOptions<TrafficMapOptions> options,
    TimeProvider timeProvider)
{
    private const int MetadataLimit = 8;
    private readonly TrafficMapOptions options = options.Value;

    public async Task<NetworkGeographyResponse> GetAsync(NetworkGeographyQuery query, CancellationToken cancellationToken)
    {
        var geoMatches = await geolocation.SearchCachedIpsAsync(query.Query, query.CountryCode, query.Asn, NetworkGeographyQuery.MaxCandidates + 1, cancellationToken);
        var geoFilterTruncated = geoMatches.Count > NetworkGeographyQuery.MaxCandidates;
        var geoFilterIps = geoMatches.Take(NetworkGeographyQuery.MaxCandidates).ToArray();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var retained = await LoadRetainedRangeAsync(connection, cancellationToken);
        var totals = await LoadTotalsAsync(connection, query, geoFilterIps, cancellationToken);
        var candidates = await LoadDestinationsAsync(connection, query, geoFilterIps, cancellationToken);
        if (candidates.Count > NetworkGeographyQuery.MaxCandidates) candidates.RemoveAt(candidates.Count - 1);
        var cached = await geolocation.GetCachedAsync(candidates.Select(item => item.DestinationIp), cancellationToken);
        var joined = candidates.Select(item => ApplyGeolocation(item, cached.GetValueOrDefault(item.DestinationIp))).ToArray();
        var resultTruncated = joined.Length > query.Limit;
        var destinations = joined.Take(query.Limit).ToArray();
        var timeline = await LoadTimelineAsync(connection, query, geoFilterIps, retained, cancellationToken);
        var health = await LoadHealthAsync(connection, query, cancellationToken);
        return new()
        {
            RetainedFromUtc = retained.From,
            RetainedToUtc = retained.To,
            FromUtc = query.From ?? retained.From,
            ToUtc = query.To ?? retained.To,
            GeneratedAtUtc = timeProvider.GetUtcNow(),
            Origin = new() { Label = options.Origin.Label, Latitude = options.Origin.Latitude!.Value, Longitude = options.Origin.Longitude!.Value },
            Map = new() { TileUrl = options.Map.TileUrl, Attribution = options.Map.Attribution },
            Summary = new()
            {
                MatchedLifecycleEvents = totals.LifecycleEvents,
                ConnectionObservations = totals.ConnectionObservations,
                UniqueDestinations = totals.UniqueDestinations,
                ReturnedDestinations = destinations.Length,
                GeolocatedDestinations = destinations.Count(item => item.GeolocationStatus == "ready"),
                PendingDestinations = destinations.Count(item => item.GeolocationStatus == "pending"),
                UnmappedDestinations = destinations.Count(item => item.GeolocationStatus is "unmapped" or "provider_error" or "disabled"),
                QuotaLimitedDestinations = destinations.Count(item => item.GeolocationStatus == "quota_limited"),
                CandidateTruncated = geoFilterTruncated || totals.UniqueDestinations > NetworkGeographyQuery.MaxCandidates,
                ResultTruncated = resultTruncated
            },
            Destinations = destinations,
            Timeline = timeline,
            Coverage = new()
            {
                SourceStatusCounts = health,
                ProcessAttributionPartial = totals.ProcessAttributionPartial
            },
            ActiveFilters = query.ActiveFilters(),
            ResultScope = $"Remote peer snapshot and kernel-flow observations over {(query.From.HasValue || query.To.HasValue ? "the selected UTC range" : "all retained event time")}; top {query.Limit} destinations; service-authenticated.",
            Limitations =
            [
                "Snapshot polling can miss short-lived sockets and does not capture packets, byte volumes, or direction; kernel-flow records are identified separately.",
                "Kernel packet and byte totals are cgroup SKB observations, not wire-accurate counters; offload and segmentation affect them.",
                "IP geolocation is approximate and can describe a provider, CDN, VPN, or anycast registration rather than a physical server.",
                "Process attribution is optional and may be unavailable or partial."
            ]
        };
    }

    private static async Task<(DateTimeOffset? From, DateTimeOffset? To)> LoadRetainedRangeAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select min(event_time), max(event_time) from events where source_id in (@snapshot_source,@kernel_source) and destination_ip is not null;";
        command.Parameters.AddWithValue("snapshot_source", LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff);
        command.Parameters.AddWithValue("kernel_source", LinuxTelemetrySourceIds.NetworkFlowSummary);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken) || reader.IsDBNull(0)) return (null, null);
        return (ReadTime(reader, 0), ReadTime(reader, 1));
    }

    private static async Task<GeographyTotals> LoadTotalsAsync(
        NpgsqlConnection connection,
        NetworkGeographyQuery query,
        IReadOnlyList<string> geoFilterIps,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        var where = BuildWhere(command, query, geoFilterIps);
        command.CommandText = $"""
            select count(*)::bigint,
                count(*) filter (where event_code in ('socket_observed','socket_baseline','network_flow_started','network_flow_sample','network_flow_closed'))::bigint,
                count(distinct destination_ip)::bigint,
                coalesce(bool_or(process_image is null),false)
            from events where {where};
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetBoolean(3));
    }

    private static async Task<List<NetworkGeographyDestination>> LoadDestinationsAsync(
        NpgsqlConnection connection,
        NetworkGeographyQuery query,
        IReadOnlyList<string> geoFilterIps,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        var where = BuildWhere(command, query, geoFilterIps);
        command.Parameters.AddWithValue("candidate_limit", NetworkGeographyQuery.MaxCandidates + 1);
        command.CommandText = $"""
            with filtered as materialized (
                select destination_ip,event_code,event_time,hostname,agent_id,process_image,
                    coalesce(normalized_json->>'protocol', normalized_json->'network'->>'protocol') as protocol,
                    coalesce(normalized_json->'network'->>'remote_port',normalized_json->>'destination_port', normalized_json->'network'->>'destination_port') as destination_port,
                    coalesce(normalized_json->'network'->>'evidence_mode',raw_json->>'evidence_mode','snapshot_diff') as evidence_mode,
                    coalesce(normalized_json->'network'->>'direction',raw_json->>'direction','unknown') as direction,
                    case when coalesce(normalized_json->'network'->>'packet_count_delta','') ~ '^[0-9]+$'
                        and length(normalized_json->'network'->>'packet_count_delta') <= 19
                        then least((normalized_json->'network'->>'packet_count_delta')::numeric,9223372036854775807)::bigint else 0 end as packet_count_delta,
                    case when coalesce(normalized_json->'network'->>'byte_count_delta','') ~ '^[0-9]+$'
                        and length(normalized_json->'network'->>'byte_count_delta') <= 19
                        then least((normalized_json->'network'->>'byte_count_delta')::numeric,9223372036854775807)::bigint else 0 end as byte_count_delta
                from events where {where}
            ), aggregated as (
                select destination_ip,
                    count(*)::bigint as lifecycle_events,
                    count(*) filter (where event_code in ('socket_observed','socket_baseline','network_flow_started','network_flow_sample','network_flow_closed'))::bigint as connection_observations,
                    count(*) filter (where event_code = 'socket_baseline')::bigint as baseline_observations,
                    count(*) filter (where event_code in ('socket_observed','network_flow_started'))::bigint as new_observations,
                    count(*) filter (where event_code in ('socket_changed','network_flow_sample'))::bigint as change_events,
                    count(*) filter (where event_code in ('socket_disappeared','socket_baseline_disappeared','network_flow_closed'))::bigint as disappearance_events,
                    sum(packet_count_delta)::bigint as packet_count_delta,
                    sum(byte_count_delta)::bigint as byte_count_delta,
                    min(event_time) as first_seen, max(event_time) as last_seen
                from filtered
                group by destination_ip
                order by (count(*) filter (where event_code in ('socket_observed','socket_baseline','network_flow_started','network_flow_sample','network_flow_closed'))) desc, max(event_time) desc, destination_ip asc
                limit @candidate_limit
            ), metadata_values as (
                select distinct f.destination_ip,'protocol'::text as kind,f.protocol as value from filtered f join aggregated a using(destination_ip) where f.protocol is not null
                union all
                select distinct f.destination_ip,'destination_port',f.destination_port from filtered f join aggregated a using(destination_ip) where f.destination_port is not null
                union all
                select distinct f.destination_ip,'hostname',f.hostname from filtered f join aggregated a using(destination_ip) where f.hostname is not null
                union all
                select distinct f.destination_ip,'agent_id',f.agent_id from filtered f join aggregated a using(destination_ip) where f.agent_id is not null
                union all
                select distinct f.destination_ip,'process_image',f.process_image from filtered f join aggregated a using(destination_ip) where f.process_image is not null
                union all
                select distinct f.destination_ip,'evidence_mode',f.evidence_mode from filtered f join aggregated a using(destination_ip) where f.evidence_mode is not null
                union all
                select distinct f.destination_ip,'direction',f.direction from filtered f join aggregated a using(destination_ip) where f.direction is not null
            ), metadata as (
                select destination_ip,
                    coalesce(array_agg(value order by value) filter (where kind='protocol'),array[]::text[]) as protocols,
                    coalesce(array_agg(value order by value) filter (where kind='destination_port'),array[]::text[]) as destination_ports,
                    coalesce(array_agg(value order by value) filter (where kind='hostname'),array[]::text[]) as hostnames,
                    coalesce(array_agg(value order by value) filter (where kind='agent_id'),array[]::text[]) as agent_ids,
                    coalesce(array_agg(value order by value) filter (where kind='process_image'),array[]::text[]) as process_images,
                    coalesce(array_agg(value order by value) filter (where kind='evidence_mode'),array[]::text[]) as evidence_modes,
                    coalesce(array_agg(value order by value) filter (where kind='direction'),array[]::text[]) as directions
                from (
                    select destination_ip,kind,value,row_number() over(partition by destination_ip,kind order by value) as ordinal
                    from metadata_values
                ) ranked
                where ordinal <= 8
                group by destination_ip
            )
            select aggregated.*,
                coalesce(metadata.protocols,array[]::text[]) as protocols,
                coalesce(metadata.destination_ports,array[]::text[]) as destination_ports,
                coalesce(metadata.hostnames,array[]::text[]) as hostnames,
                coalesce(metadata.agent_ids,array[]::text[]) as agent_ids,
                coalesce(metadata.process_images,array[]::text[]) as process_images,
                coalesce(metadata.evidence_modes,array[]::text[]) as evidence_modes,
                coalesce(metadata.directions,array[]::text[]) as directions
            from aggregated
            left join metadata using(destination_ip)
            order by connection_observations desc nulls last, last_seen desc, destination_ip asc;
            """;
        var results = new List<NetworkGeographyDestination>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var baselines = reader.GetInt64(reader.GetOrdinal("baseline_observations"));
            var observed = reader.GetInt64(reader.GetOrdinal("new_observations"));
            results.Add(new()
            {
                DestinationIp = reader.GetString(reader.GetOrdinal("destination_ip")),
                LifecycleEvents = reader.GetInt64(reader.GetOrdinal("lifecycle_events")),
                BaselineObservations = baselines,
                NewObservations = observed,
                ConnectionObservations = reader.GetInt64(reader.GetOrdinal("connection_observations")),
                ChangeEvents = reader.GetInt64(reader.GetOrdinal("change_events")),
                DisappearanceEvents = reader.GetInt64(reader.GetOrdinal("disappearance_events")),
                PacketCountDelta = reader.GetInt64(reader.GetOrdinal("packet_count_delta")),
                ByteCountDelta = reader.GetInt64(reader.GetOrdinal("byte_count_delta")),
                FirstSeenUtc = ReadTime(reader, reader.GetOrdinal("first_seen")),
                LastSeenUtc = ReadTime(reader, reader.GetOrdinal("last_seen")),
                Protocols = ReadStrings(reader, "protocols"),
                DestinationPorts = ReadStrings(reader, "destination_ports").Select(value => int.TryParse(value, out var port) ? port : 0).Where(port => port > 0).Take(MetadataLimit).ToArray(),
                Hostnames = ReadStrings(reader, "hostnames"),
                AgentIds = ReadStrings(reader, "agent_ids"),
                ProcessImages = ReadStrings(reader, "process_images"),
                EvidenceModes = ReadStrings(reader, "evidence_modes"),
                Directions = ReadStrings(reader, "directions")
            });
        }
        return results;
    }

    private static async Task<IReadOnlyList<NetworkGeographyTimelineBucket>> LoadTimelineAsync(
        NpgsqlConnection connection,
        NetworkGeographyQuery query,
        IReadOnlyList<string> geoFilterIps,
        (DateTimeOffset? From, DateTimeOffset? To) retained,
        CancellationToken cancellationToken)
    {
        var start = query.From ?? retained.From ?? DateTimeOffset.UtcNow.AddHours(-1);
        var end = query.To ?? retained.To ?? DateTimeOffset.UtcNow;
        var seconds = Math.Max(60, (long)Math.Ceiling(Math.Max(1, (end - start).TotalSeconds) / 200d));
        var choices = new[] { 60L, 300, 900, 3600, 21600, 43200, 86400, 604800, 2592000 };
        var bucketSeconds = choices.FirstOrDefault(choice => choice >= seconds, seconds);
        await using var command = connection.CreateCommand();
        var where = BuildWhere(command, query, geoFilterIps);
        command.Parameters.AddWithValue("bucket_seconds", bucketSeconds);
        command.CommandText = $"""
            select to_timestamp(floor(extract(epoch from event_time) / @bucket_seconds) * @bucket_seconds) as bucket_start,
                count(*) filter (where event_code in ('socket_observed','socket_baseline','network_flow_started','network_flow_sample','network_flow_closed'))::bigint as connection_observations,
                count(*)::bigint as lifecycle_events
            from events where {where}
            group by bucket_start order by bucket_start asc limit 200;
            """;
        var results = new List<NetworkGeographyTimelineBucket>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var bucketStart = ReadTime(reader, 0);
            results.Add(new()
            {
                StartUtc = bucketStart,
                EndUtc = bucketStart.AddSeconds(bucketSeconds),
                ConnectionObservations = reader.GetInt64(1),
                LifecycleEvents = reader.GetInt64(2)
            });
        }
        return results;
    }

    private static async Task<IReadOnlyDictionary<string, long>> LoadHealthAsync(
        NpgsqlConnection connection,
        NetworkGeographyQuery query,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        var where = new List<string> { "health.source_id in (@snapshot_source,@kernel_source)" };
        command.Parameters.AddWithValue("snapshot_source", LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff);
        command.Parameters.AddWithValue("kernel_source", LinuxTelemetrySourceIds.NetworkFlowSummary);
        if (query.AgentId is not null)
        {
            where.Add("health.agent_id=@health_agent_id");
            command.Parameters.AddWithValue("health_agent_id", query.AgentId);
        }
        if (query.Hostname is not null)
        {
            where.Add("agent.hostname=@health_hostname");
            command.Parameters.AddWithValue("health_hostname", query.Hostname);
        }
        command.CommandText = $"select health.status,count(*)::bigint from source_health health join agents agent on agent.agent_id=health.agent_id where {string.Join(" and ", where)} group by health.status order by health.status;";
        var results = new Dictionary<string, long>(StringComparer.Ordinal);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results[reader.GetString(0)] = reader.GetInt64(1);
        return results;
    }

    private static string BuildWhere(NpgsqlCommand command, NetworkGeographyQuery query, IReadOnlyList<string> geoFilterIps)
    {
        var where = new List<string> { "source_id in (@snapshot_source,@kernel_source)", "destination_ip is not null" };
        command.Parameters.AddWithValue("snapshot_source", LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff);
        command.Parameters.AddWithValue("kernel_source", LinuxTelemetrySourceIds.NetworkFlowSummary);
        void Exact(string column, string parameter, string? value)
        {
            if (value is null) return;
            where.Add($"{column} = @{parameter}");
            command.Parameters.AddWithValue(parameter, value);
        }
        Exact("hostname", "hostname", query.Hostname);
        Exact("agent_id", "agent_id", query.AgentId);
        Exact("destination_ip", "destination_ip", query.DestinationIp);
        if (query.From.HasValue) { where.Add("event_time >= @from"); command.Parameters.AddWithValue("from", query.From.Value.ToUniversalTime()); }
        if (query.To.HasValue) { where.Add("event_time <= @to"); command.Parameters.AddWithValue("to", query.To.Value.ToUniversalTime()); }
        if (query.DestinationPort.HasValue)
        {
            where.Add("coalesce(normalized_json->'network'->>'remote_port',normalized_json->>'destination_port', normalized_json->'network'->>'destination_port') = @destination_port");
            command.Parameters.AddWithValue("destination_port", query.DestinationPort.Value.ToString(CultureInfo.InvariantCulture));
        }
        if (query.Protocol is not null)
        {
            where.Add("coalesce(normalized_json->>'protocol', normalized_json->'network'->>'protocol') = @protocol");
            command.Parameters.AddWithValue("protocol", query.Protocol);
        }
        if (query.ProcessImage is not null)
        {
            where.Add("process_image ilike @process_image escape '\\'");
            command.Parameters.AddWithValue("process_image", $"%{EscapeLike(query.ProcessImage)}%");
        }
        if (query.CountryCode is not null || query.Asn.HasValue)
        {
            where.Add("destination_ip = any(@geo_filter_ips)");
            command.Parameters.AddWithValue("geo_filter_ips", geoFilterIps.ToArray());
        }
        if (query.Query is not null)
        {
            where.Add("(destination_ip ilike @query escape '\\' or hostname ilike @query escape '\\' or agent_id ilike @query escape '\\' or coalesce(process_image,'') ilike @query escape '\\' or coalesce(normalized_json->>'protocol', normalized_json->'network'->>'protocol','') ilike @query escape '\\' or coalesce(normalized_json->>'destination_port', normalized_json->'network'->>'destination_port','') ilike @query escape '\\' or destination_ip = any(@geo_query_ips))");
            command.Parameters.AddWithValue("query", $"%{EscapeLike(query.Query)}%");
            command.Parameters.AddWithValue("geo_query_ips", geoFilterIps.ToArray());
        }
        return string.Join(" and ", where);
    }

    private NetworkGeographyDestination ApplyGeolocation(NetworkGeographyDestination destination, IpGeolocationRecord? geo) =>
        destination with
        {
            GeolocationStatus = geo?.Status ?? (IpAddressScopeClassifier.IsPubliclyRoutable(destination.DestinationIp)
                ? options.Geolocation.Enabled ? "pending" : "disabled"
                : "unmapped"),
            Latitude = geo?.Latitude,
            Longitude = geo?.Longitude,
            City = geo?.City,
            Region = geo?.Region,
            Country = geo?.Country,
            CountryCode = geo?.CountryCode,
            Continent = geo?.Continent,
            Asn = geo?.Asn,
            Organization = geo?.Organization,
            Isp = geo?.Isp,
            GeolocationFetchedAtUtc = geo?.FetchedAtUtc
        };

    private static string[] ReadStrings(NpgsqlDataReader reader, string name) =>
        reader.IsDBNull(reader.GetOrdinal(name)) ? Array.Empty<string>() : reader.GetFieldValue<string[]>(reader.GetOrdinal(name)).Where(value => !string.IsNullOrWhiteSpace(value)).OrderBy(value => value, StringComparer.Ordinal).Take(MetadataLimit).ToArray();
    private static DateTimeOffset ReadTime(NpgsqlDataReader reader, int ordinal) => reader.GetFieldValue<DateTimeOffset>(ordinal).ToUniversalTime();
    private static string EscapeLike(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);
    private sealed record GeographyTotals(long LifecycleEvents, long ConnectionObservations, long UniqueDestinations, bool ProcessAttributionPartial);
}
