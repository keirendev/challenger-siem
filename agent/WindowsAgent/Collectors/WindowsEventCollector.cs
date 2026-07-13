using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Normalization;
using Challenger.Siem.WindowsAgent.Security;
using Challenger.Siem.WindowsAgent.Serialization;
using Challenger.Siem.WindowsAgent.Time;
using Challenger.Siem.WindowsAgent.Util;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.WindowsAgent.Collectors;

public sealed class WindowsEventCollector(
    IOptions<AgentOptions> options,
    ILogger<WindowsEventCollector> logger) : IWindowsEventCollector
{
    private readonly AgentOptions options = options.Value;
    private readonly string hostname = Environment.MachineName;
    private readonly ConcurrentDictionary<string, byte> missingChannelsLogged = new(StringComparer.OrdinalIgnoreCase);

    public Task<long?> GetLatestRecordIdAsync(string channel, CancellationToken cancellationToken)
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName, "*")
            {
                ReverseDirection = true
            });

            cancellationToken.ThrowIfCancellationRequested();
            using var record = reader.ReadEvent();
            return Task.FromResult(record?.RecordId);
        }
        catch (EventLogNotFoundException)
        {
            LogChannelNotPresentOnce(channel);
            return Task.FromResult<long?>(null);
        }
        catch (EventLogException ex)
        {
            logger.LogWarning(ex, "Could not read latest record ID for Windows Event Log channel {Channel}.", channel);
            return Task.FromResult<long?>(null);
        }
    }

    public Task<SourceHealthReport> ProbeChannelAsync(SourceManifestEntry source, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            bool enabled;
            long? logSizeBytes;
            using (var config = new EventLogConfiguration(source.Channel))
            {
                enabled = config.IsEnabled;
                logSizeBytes = config.MaximumSizeInBytes;
            }

            if (!enabled)
            {
                var disabledDetails = CreateSourceDetails(source, out var disabledConfigHash, out var disabledSourceVersion);
                return Task.FromResult(new SourceHealthReport
                {
                    SourceId = source.SourceId,
                    DisplayName = source.DisplayName,
                    Channel = source.Channel,
                    CoverageLevel = source.CoverageLevel,
                    Required = source.Required,
                    Enabled = false,
                    Status = SourceHealthStatuses.Disabled,
                    LogSizeBytes = logSizeBytes,
                    HostTimezone = HostTimezoneProvider.Current(),
                    ErrorCode = "event_log_disabled",
                    ErrorMessage = "Channel exists but is disabled on this host.",
                    ConfigHash = disabledConfigHash,
                    SourceVersion = disabledSourceVersion,
                    Details = disabledDetails
                });
            }

            long? latest = null;
            DateTimeOffset? latestEventTime = null;
            using (var reverseReader = new EventLogReader(new EventLogQuery(source.Channel, PathType.LogName, "*")
            {
                ReverseDirection = true
            }))
            {
                using var latestRecord = reverseReader.ReadEvent();
                latest = latestRecord?.RecordId;
                latestEventTime = latestRecord is null ? null : HostTimezoneProvider.ToUtc(latestRecord.TimeCreated);
            }

            long? oldest = null;
            try
            {
                using var forwardReader = new EventLogReader(new EventLogQuery(source.Channel, PathType.LogName, "*")
                {
                    ReverseDirection = false
                });
                using var first = forwardReader.ReadEvent();
                oldest = first?.RecordId;
            }
            catch (EventLogException)
            {
                // The latest probe already captures source readability; oldest is best effort.
            }

            var details = CreateSourceDetails(source, out var configHash, out var sourceVersion);
            if (!latest.HasValue)
            {
                details["empty_enabled_log"] = "true";
            }

            return Task.FromResult(new SourceHealthReport
            {
                SourceId = source.SourceId,
                DisplayName = source.DisplayName,
                Channel = source.Channel,
                CoverageLevel = source.CoverageLevel,
                Required = source.Required,
                Enabled = true,
                Status = SourceHealthStatuses.Healthy,
                LastEventTime = latestEventTime,
                LastRecordId = latest,
                OldestRecordId = oldest,
                NewestRecordId = latest,
                LogSizeBytes = logSizeBytes,
                HostTimezone = latestEventTime.HasValue ? HostTimezoneProvider.ForInstant(latestEventTime.Value) : HostTimezoneProvider.Current(),
                ConfigHash = configHash,
                SourceVersion = sourceVersion,
                Details = details
            });
        }
        catch (EventLogNotFoundException)
        {
            LogChannelNotPresentOnce(source.Channel!);
            return Task.FromResult(SourceProbeError(source, SourceHealthStatuses.Missing, "event_log_not_found", "Channel is not present on this host."));
        }
        catch (EventLogException ex)
        {
            logger.LogWarning(ex, "Could not probe Windows Event Log channel {Channel}.", source.Channel);
            return Task.FromResult(SourceProbeError(source, SourceHealthStatuses.Error, ex.GetType().Name, ex.Message));
        }
    }

    public Task<IReadOnlyList<CollectedWindowsEvent>> ReadEventsAsync(
        string channel,
        long? afterRecordId,
        int maxEvents,
        CancellationToken cancellationToken)
    {
        var events = new List<CollectedWindowsEvent>(Math.Max(1, maxEvents));

        try
        {
            var queryText = afterRecordId.HasValue
                ? $"*[System[EventRecordID>{afterRecordId.Value}]]"
                : "*";

            using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName, queryText)
            {
                ReverseDirection = false
            });

            while (events.Count < maxEvents)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null)
                {
                    break;
                }

                if (!record.RecordId.HasValue)
                {
                    continue;
                }

                events.Add(new CollectedWindowsEvent(record.RecordId.Value, MapRecord(channel, record)));
            }
        }
        catch (EventLogNotFoundException)
        {
            LogChannelNotPresentOnce(channel);
        }
        catch (EventLogException ex)
        {
            logger.LogWarning(ex, "Could not read Windows Event Log channel {Channel}.", channel);
        }

        return Task.FromResult<IReadOnlyList<CollectedWindowsEvent>>(events);
    }

    private EventEnvelope MapRecord(string requestedChannel, EventRecord record)
    {
        var channel = ReadString(() => record.LogName) ?? requestedChannel;
        var provider = ReadString(() => record.ProviderName) ?? string.Empty;
        var recordId = record.RecordId ?? 0;
        var eventTime = HostTimezoneProvider.ToUtc(record.TimeCreated);
        var hostTimezone = HostTimezoneProvider.ForInstant(eventTime);
        var windowsEventId = record.Id;
        var keywords = ReadKeywords(record);
        var message = Truncate(ReadString(record.FormatDescription) ?? string.Empty, 20000) ?? string.Empty;
        var xml = Truncate(ReadString(record.ToXml), 20000);
        var rawProperties = record.Properties
            .Select((property, index) => new
            {
                index,
                value = Truncate(property.Value?.ToString(), 4096)
            })
            .ToArray();

        var eventId = DeterministicGuid.Create(
            options.AgentId,
            channel,
            recordId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            provider,
            windowsEventId.ToString(System.Globalization.CultureInfo.InvariantCulture));

        var raw = JsonDefaults.ToJsonElement(new
        {
            original = new
            {
                xml,
                level = record.Level,
                level_display_name = ReadString(() => record.LevelDisplayName),
                opcode = record.Opcode,
                opcode_display_name = ReadString(() => record.OpcodeDisplayName),
                task = record.Task,
                task_display_name = ReadString(() => record.TaskDisplayName),
                keywords,
                properties = rawProperties
            }
        });

        return new EventEnvelope
        {
            EventId = eventId,
            AgentId = options.AgentId,
            Hostname = hostname,
            Source = EventSources.WindowsEventLog,
            Channel = channel,
            Provider = provider,
            WindowsEventId = windowsEventId,
            RecordId = recordId,
            EventTime = eventTime,
            HostTimezone = hostTimezone,
            IngestTime = null,
            Severity = WindowsEventSeverityMapper.Map(record.Level, keywords),
            Message = message,
            Normalized = WindowsEventNormalizer.Normalize(channel, provider, windowsEventId, message),
            Raw = raw
        };
    }

    private SourceHealthReport SourceProbeError(SourceManifestEntry source, string status, string errorCode, string errorMessage)
    {
        var details = CreateSourceDetails(source, out var configHash, out var sourceVersion);
        return new SourceHealthReport
        {
            SourceId = source.SourceId,
            DisplayName = source.DisplayName,
            Channel = source.Channel,
            CoverageLevel = source.CoverageLevel,
            Required = source.Required,
            Enabled = true,
            Status = status,
            HostTimezone = HostTimezoneProvider.Current(),
            ErrorCode = errorCode,
            ErrorMessage = errorMessage.Length <= 500 ? errorMessage : errorMessage[..500],
            ConfigHash = configHash,
            SourceVersion = sourceVersion,
            Details = details
        };
    }

    private Dictionary<string, string> CreateSourceDetails(SourceManifestEntry source, out string? configHash, out string? sourceVersion)
    {
        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["parser_id"] = source.ParserId,
            ["source_pack"] = source.SourcePack
        };

        configHash = null;
        sourceVersion = null;
        if (!string.Equals(source.ParserId, "sysmon", StringComparison.OrdinalIgnoreCase))
        {
            return details;
        }

        sourceVersion = options.Sysmon.ProfileVersion;
        details["sysmon_profile_version"] = string.IsNullOrWhiteSpace(options.Sysmon.ProfileVersion)
            ? "unknown"
            : options.Sysmon.ProfileVersion;
        details["sysmon_config_path_configured"] = string.IsNullOrWhiteSpace(options.Sysmon.ConfigPath) ? "false" : "true";

        if (string.IsNullOrWhiteSpace(options.Sysmon.ConfigPath))
        {
            details["sysmon_config_file_present"] = "false";
            return details;
        }

        try
        {
            if (File.Exists(options.Sysmon.ConfigPath))
            {
                configHash = AgentConfigurationHasher.ComputeFileHash(options.Sysmon.ConfigPath);
                details["sysmon_config_file_present"] = "true";
            }
            else
            {
                details["sysmon_config_file_present"] = "false";
            }
        }
        catch (IOException)
        {
            details["sysmon_config_file_present"] = "error";
        }
        catch (UnauthorizedAccessException)
        {
            details["sysmon_config_file_present"] = "error";
        }

        return details;
    }

    private static string? Truncate(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value[..maxLength];
    }

    private static IReadOnlyList<string> ReadKeywords(EventRecord record)
    {
        try
        {
            return record.KeywordsDisplayNames?.ToArray() ?? Array.Empty<string>();
        }
        catch (EventLogException)
        {
            return Array.Empty<string>();
        }
    }

    private void LogChannelNotPresentOnce(string channel)
    {
        if (missingChannelsLogged.TryAdd(channel, 0))
        {
            logger.LogInformation("Windows Event Log channel {Channel} is not present. Future checks for this missing channel will be silent.", channel);
        }
    }

    private static string? ReadString(Func<string?> read)
    {
        try
        {
            return read();
        }
        catch (EventLogException)
        {
            return null;
        }
    }
}
