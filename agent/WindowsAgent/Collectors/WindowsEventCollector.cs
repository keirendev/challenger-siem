using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Normalization;
using Challenger.Siem.WindowsAgent.Serialization;
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
            var latest = GetLatestRecordIdAsync(source.Channel, cancellationToken).GetAwaiter().GetResult();
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
                // The latest probe already captures the source health status; oldest is best effort.
            }

            long? logSizeBytes = null;
            try
            {
                using var config = new EventLogConfiguration(source.Channel);
                logSizeBytes = config.MaximumSizeInBytes;
            }
            catch (EventLogException)
            {
                // Best effort only; not all channels expose a size through the API for every caller.
            }

            var status = latest.HasValue ? SourceHealthStatuses.Healthy : SourceHealthStatuses.Missing;
            return Task.FromResult(new SourceHealthReport
            {
                SourceId = source.SourceId,
                DisplayName = source.DisplayName,
                Channel = source.Channel,
                CoverageLevel = source.CoverageLevel,
                Required = source.Required,
                Enabled = true,
                Status = status,
                LastRecordId = latest,
                OldestRecordId = oldest,
                NewestRecordId = latest,
                LogSizeBytes = logSizeBytes,
                Details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["parser_id"] = source.ParserId,
                    ["source_pack"] = source.SourcePack
                }
            });
        }
        catch (EventLogNotFoundException)
        {
            LogChannelNotPresentOnce(source.Channel);
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
        var eventTime = ToUtc(record.TimeCreated);
        var windowsEventId = record.Id;
        var keywords = ReadKeywords(record);
        var message = ReadString(record.FormatDescription) ?? string.Empty;
        var xml = ReadString(record.ToXml);
        var rawProperties = record.Properties
            .Select((property, index) => new
            {
                index,
                value = property.Value?.ToString()
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
            IngestTime = null,
            Severity = WindowsEventSeverityMapper.Map(record.Level, keywords),
            Message = message,
            Normalized = WindowsEventNormalizer.Normalize(channel, provider, windowsEventId, message),
            Raw = raw
        };
    }

    private static SourceHealthReport SourceProbeError(SourceManifestEntry source, string status, string errorCode, string errorMessage)
    {
        return new SourceHealthReport
        {
            SourceId = source.SourceId,
            DisplayName = source.DisplayName,
            Channel = source.Channel,
            CoverageLevel = source.CoverageLevel,
            Required = source.Required,
            Enabled = true,
            Status = status,
            ErrorCode = errorCode,
            ErrorMessage = errorMessage.Length <= 500 ? errorMessage : errorMessage[..500],
            Details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["parser_id"] = source.ParserId,
                ["source_pack"] = source.SourcePack
            }
        };
    }

    private static DateTimeOffset ToUtc(DateTime? dateTime)
    {
        if (!dateTime.HasValue)
        {
            return DateTimeOffset.UtcNow;
        }

        return dateTime.Value.Kind switch
        {
            DateTimeKind.Utc => new DateTimeOffset(dateTime.Value),
            DateTimeKind.Local => new DateTimeOffset(dateTime.Value).ToUniversalTime(),
            _ => new DateTimeOffset(DateTime.SpecifyKind(dateTime.Value, DateTimeKind.Utc))
        };
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
