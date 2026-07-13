using System.Globalization;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Http;

namespace Challenger.Siem.Api.Database;

public sealed record EventSearchValidationError(string Field, string Message);

public sealed record EventSearchCursor(DateTimeOffset EventTime, long RowId)
{
    public static string Encode(DateTimeOffset eventTime, long rowId)
    {
        var json = JsonSerializer.Serialize(new EventSearchCursor(eventTime.ToUniversalTime(), rowId));
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static EventSearchCursor? TryDecode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 512)
        {
            return null;
        }

        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded = padded.PadRight(padded.Length + ((4 - padded.Length % 4) % 4), '=');
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
            var cursor = JsonSerializer.Deserialize<EventSearchCursor>(json);
            return cursor is { RowId: > 0 } && cursor.EventTime != default ? cursor with { EventTime = cursor.EventTime.ToUniversalTime() } : null;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException)
        {
            return null;
        }
    }
}

public sealed record EventSearchQuery
{
    public const int DefaultLimit = 100;
    public const int MaxLimit = 500;
    public const int MaxExportLimit = 5000;
    public const int DefaultTimelineBucketSeconds = 3600;

    private static readonly HashSet<string> AllowedColumns = new(StringComparer.Ordinal)
    {
        "event_time", "host", "agent_id", "platform", "source", "provider", "code", "severity", "outcome", "category", "action", "user", "process", "service", "file", "network", "message", "ingest_time", "pivots"
    };

    private static readonly HashSet<string> ProtectedFilterNames = new(StringComparer.Ordinal)
    {
        "keyword", "user_name", "process_image", "process_command_line", "source_ip", "destination_ip", "network_ip", "service_name", "file_path", "registry_key", "package_name", "entity_value"
    };

    public string? Hostname { get; init; }
    public string? AgentId { get; init; }
    public string? Channel { get; init; }
    public int? WindowsEventId { get; init; }
    public DateTimeOffset? From { get; init; }
    public DateTimeOffset? To { get; init; }
    public string? Keyword { get; init; }
    public string? Category { get; init; }
    public string? Action { get; init; }
    public string? Outcome { get; init; }
    public string? UserName { get; init; }
    public string? ProcessImage { get; init; }
    public string? ProcessCommandLine { get; init; }
    public string? SourceIp { get; init; }
    public string? DestinationIp { get; init; }
    public string? NetworkIp { get; init; }
    public string? SourcePort { get; init; }
    public string? DestinationPort { get; init; }
    public string? Protocol { get; init; }
    public string? ServiceName { get; init; }
    public string? FilePath { get; init; }
    public string? RegistryKey { get; init; }
    public string? Source { get; init; }
    public string? Platform { get; init; }
    public string? SourceId { get; init; }
    public string? EventCode { get; init; }
    public string? Provider { get; init; }
    public string? Facility { get; init; }
    public string? Unit { get; init; }
    public string? Severity { get; init; }
    public string? PackageName { get; init; }
    public string? DetectionRuleId { get; init; }
    public string? EntityType { get; init; }
    public string? EntityValue { get; init; }
    public int Limit { get; init; } = DefaultLimit;
    public string? Cursor { get; init; }
    public int BucketSeconds { get; init; } = DefaultTimelineBucketSeconds;
    public IReadOnlyList<string> Columns { get; init; } = Array.Empty<string>();
    public IReadOnlyList<EventSearchValidationError> ValidationErrors { get; init; } = Array.Empty<EventSearchValidationError>();

    public static EventSearchQuery Empty => new();

    public static EventSearchQuery FromQuery(IQueryCollection query, int maxLimit = MaxLimit)
    {
        var errors = new List<EventSearchValidationError>();
        DateTimeOffset? from = ReadDateTimeOffset(query, "from", errors);
        DateTimeOffset? to = ReadDateTimeOffset(query, "to", errors);
        if (from.HasValue && to.HasValue && from.Value > to.Value)
        {
            errors.Add(new("time", "from must be earlier than or equal to to."));
        }

        var columns = ReadColumns(query, errors);
        var limit = ReadInt(query, "limit", errors, 1, Math.Clamp(maxLimit, 1, MaxExportLimit)) ?? DefaultLimit;
        var bucketSeconds = ReadInt(query, "bucket_seconds", errors, 60, 86400) ?? DefaultTimelineBucketSeconds;
        var cursor = ReadString(query, "cursor", errors, 512, allowSymbols: true);
        if (cursor is not null && EventSearchCursor.TryDecode(cursor) is null)
        {
            errors.Add(new("cursor", "cursor is invalid or expired."));
        }

        var result = new EventSearchQuery
        {
            Hostname = ReadString(query, "hostname", errors, 128),
            AgentId = ReadString(query, "agent_id", errors, 128),
            Channel = ReadString(query, "channel", errors, 160, allowSymbols: true),
            WindowsEventId = ReadInt(query, "windows_event_id", errors, 0, 65535),
            From = from,
            To = to,
            Keyword = ReadString(query, "keyword", errors, 160, allowSymbols: true),
            Category = ReadString(query, "category", errors, 64),
            Action = ReadString(query, "action", errors, 64),
            Outcome = ReadString(query, "outcome", errors, 64),
            UserName = ReadString(query, "user_name", errors, 160, allowSymbols: true),
            ProcessImage = ReadString(query, "process_image", errors, 260, allowSymbols: true),
            ProcessCommandLine = ReadString(query, "process_command_line", errors, 260, allowSymbols: true),
            SourceIp = ReadString(query, "source_ip", errors, 64, allowSymbols: true),
            DestinationIp = ReadString(query, "destination_ip", errors, 64, allowSymbols: true),
            NetworkIp = ReadString(query, "network_ip", errors, 64, allowSymbols: true),
            SourcePort = ReadString(query, "source_port", errors, 16),
            DestinationPort = ReadString(query, "destination_port", errors, 16),
            Protocol = ReadString(query, "protocol", errors, 32),
            ServiceName = ReadString(query, "service_name", errors, 160, allowSymbols: true),
            FilePath = ReadString(query, "file_path", errors, 260, allowSymbols: true),
            RegistryKey = ReadString(query, "registry_key", errors, 260, allowSymbols: true),
            Source = ReadString(query, "source", errors, 64),
            Platform = ReadString(query, "platform", errors, 32),
            SourceId = ReadString(query, "source_id", errors, 128),
            EventCode = ReadString(query, "event_code", errors, 128),
            Provider = ReadString(query, "provider", errors, 160, allowSymbols: true),
            Facility = ReadString(query, "facility", errors, 80, allowSymbols: true),
            Unit = ReadString(query, "unit", errors, 160, allowSymbols: true),
            Severity = ReadString(query, "severity", errors, 32),
            PackageName = ReadString(query, "package_name", errors, 160, allowSymbols: true),
            DetectionRuleId = ReadString(query, "detection_rule_id", errors, 160, allowSymbols: true),
            EntityType = ReadString(query, "entity_type", errors, 64),
            EntityValue = ReadString(query, "entity_value", errors, 160, allowSymbols: true),
            Limit = limit,
            Cursor = cursor,
            BucketSeconds = bucketSeconds,
            Columns = columns,
            ValidationErrors = errors
        };

        return result.ValidateEnums();
    }

    public EventSearchQuery ForRole(string role)
    {
        if (Challenger.Siem.Api.Auth.OperatorAuthorization.HasPermission(role, Challenger.Siem.Api.Auth.OperatorPermission.ReviewSensitive))
        {
            return this;
        }

        return this with
        {
            Keyword = null,
            UserName = null,
            ProcessImage = null,
            ProcessCommandLine = null,
            SourceIp = null,
            DestinationIp = null,
            NetworkIp = null,
            SourcePort = null,
            DestinationPort = null,
            Protocol = null,
            ServiceName = null,
            FilePath = null,
            RegistryKey = null,
            PackageName = null,
            EntityType = null,
            EntityValue = null
        };
    }

    public IReadOnlyList<EventSearchFilterSummary> ActiveFilterSummaries()
    {
        var filters = new List<EventSearchFilterSummary>();
        Add(filters, "from", From?.ToString("O", CultureInfo.InvariantCulture), false);
        Add(filters, "to", To?.ToString("O", CultureInfo.InvariantCulture), false);
        Add(filters, "hostname", Hostname, false);
        Add(filters, "agent_id", AgentId, false);
        Add(filters, "platform", Platform, false);
        Add(filters, "source", Source, false);
        Add(filters, "source_id", SourceId, false);
        Add(filters, "channel", Channel, false);
        Add(filters, "provider", Provider, false);
        Add(filters, "facility", Facility, false);
        Add(filters, "unit", Unit, false);
        Add(filters, "windows_event_id", WindowsEventId?.ToString(CultureInfo.InvariantCulture), false);
        Add(filters, "event_code", EventCode, false);
        Add(filters, "severity", Severity, false);
        Add(filters, "outcome", Outcome, false);
        Add(filters, "category", Category, false);
        Add(filters, "action", Action, false);
        Add(filters, "detection_rule_id", DetectionRuleId, false);
        Add(filters, "keyword", Keyword, true);
        Add(filters, "user_name", UserName, true);
        Add(filters, "process_image", ProcessImage, true);
        Add(filters, "process_command_line", ProcessCommandLine, true);
        Add(filters, "source_ip", SourceIp, true);
        Add(filters, "destination_ip", DestinationIp, true);
        Add(filters, "network_ip", NetworkIp, true);
        Add(filters, "source_port", SourcePort, true);
        Add(filters, "destination_port", DestinationPort, true);
        Add(filters, "protocol", Protocol, true);
        Add(filters, "service_name", ServiceName, true);
        Add(filters, "file_path", FilePath, true);
        Add(filters, "registry_key", RegistryKey, true);
        Add(filters, "package_name", PackageName, true);
        Add(filters, "entity_type", EntityType, false);
        Add(filters, "entity_value", EntityValue, true);
        return filters;

        static void Add(List<EventSearchFilterSummary> list, string name, string? value, bool isProtected)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                list.Add(new EventSearchFilterSummary { Name = name, Value = value.Trim(), Protected = isProtected });
            }
        }
    }

    public IReadOnlyDictionary<string, string> ToSavedQueryDictionary()
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var filter in ActiveFilterSummaries())
        {
            values[filter.Name] = filter.Value;
        }
        values["limit"] = Math.Clamp(Limit, 1, MaxLimit).ToString(CultureInfo.InvariantCulture);
        if (BucketSeconds != DefaultTimelineBucketSeconds) values["bucket_seconds"] = BucketSeconds.ToString(CultureInfo.InvariantCulture);
        if (Columns.Count > 0) values["columns"] = string.Join(',', Columns);
        return values;
    }

    public static EventSearchQuery FromSavedQuery(IReadOnlyDictionary<string, string> values)
    {
        var query = new QueryCollection(values.ToDictionary(item => item.Key, item => new Microsoft.Extensions.Primitives.StringValues(item.Value), StringComparer.OrdinalIgnoreCase));
        return FromQuery(query);
    }

    private EventSearchQuery ValidateEnums()
    {
        var errors = ValidationErrors.ToList();
        if (!string.IsNullOrWhiteSpace(Platform) && Platform is not (TelemetryPlatforms.Windows or TelemetryPlatforms.Linux)) errors.Add(new("platform", "platform must be windows or linux."));
        if (!string.IsNullOrWhiteSpace(Source) && !TelemetrySourceKinds.All.Contains(Source)) errors.Add(new("source", "source is not a supported v1 source kind."));
        if (!string.IsNullOrWhiteSpace(Severity) && Severity is not ("verbose" or "information" or "warning" or "error" or "critical" or "audit_success" or "audit_failure")) errors.Add(new("severity", "severity is not a supported v1 event severity."));
        if (!string.IsNullOrWhiteSpace(SourcePort) && !int.TryParse(SourcePort, NumberStyles.None, CultureInfo.InvariantCulture, out _)) errors.Add(new("source_port", "source_port must be numeric."));
        if (!string.IsNullOrWhiteSpace(DestinationPort) && !int.TryParse(DestinationPort, NumberStyles.None, CultureInfo.InvariantCulture, out _)) errors.Add(new("destination_port", "destination_port must be numeric."));
        if (!string.IsNullOrWhiteSpace(EntityValue) && string.IsNullOrWhiteSpace(EntityType)) errors.Add(new("entity_type", "entity_type is required when entity_value is present."));
        return this with { ValidationErrors = errors };
    }

    private static string? ReadString(IQueryCollection query, string key, List<EventSearchValidationError> errors, int maxLength, bool allowSymbols = false)
    {
        if (!query.TryGetValue(key, out var values)) return null;
        var value = values.FirstOrDefault()?.Trim();
        if (string.IsNullOrEmpty(value)) return null;
        if (value.Length > maxLength)
        {
            errors.Add(new(key, $"{key} must be {maxLength} characters or fewer."));
            return value[..maxLength];
        }

        if (!allowSymbols && value.Any(ch => !(char.IsLetterOrDigit(ch) || ch is '_' or '-' or '.' or ':' or '/')))
        {
            errors.Add(new(key, $"{key} contains unsupported characters."));
        }

        return value;
    }

    private static int? ReadInt(IQueryCollection query, string key, List<EventSearchValidationError> errors, int min, int max)
    {
        if (!query.TryGetValue(key, out var values) || string.IsNullOrWhiteSpace(values.FirstOrDefault())) return null;
        if (!int.TryParse(values.FirstOrDefault(), NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
        {
            errors.Add(new(key, $"{key} must be an integer."));
            return null;
        }
        if (parsed < min || parsed > max)
        {
            errors.Add(new(key, $"{key} must be between {min} and {max}."));
            return Math.Clamp(parsed, min, max);
        }
        return parsed;
    }

    private static DateTimeOffset? ReadDateTimeOffset(IQueryCollection query, string key, List<EventSearchValidationError> errors)
    {
        if (!query.TryGetValue(key, out var values) || string.IsNullOrWhiteSpace(values.FirstOrDefault())) return null;
        var value = values.FirstOrDefault();
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
        {
            return parsed.ToUniversalTime();
        }
        errors.Add(new(key, $"{key} must be an RFC 3339 or UTC datetime value."));
        return null;
    }

    private static IReadOnlyList<string> ReadColumns(IQueryCollection query, List<EventSearchValidationError> errors)
    {
        if (!query.TryGetValue("columns", out var values) || string.IsNullOrWhiteSpace(values.FirstOrDefault())) return Array.Empty<string>();
        var columns = values.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).Take(16).ToArray();
        foreach (var column in columns.Where(column => !AllowedColumns.Contains(column)))
        {
            errors.Add(new("columns", $"Unsupported column '{column}'."));
        }
        return columns.Where(AllowedColumns.Contains).ToArray();
    }
}
