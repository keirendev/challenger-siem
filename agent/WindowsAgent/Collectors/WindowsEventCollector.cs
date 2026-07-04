using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Config;
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
            Severity = MapSeverity(record, keywords),
            Message = message,
            Raw = raw
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

    private static string MapSeverity(EventRecord record, IReadOnlyList<string> keywords)
    {
        if (keywords.Any(keyword => keyword.Contains("Audit Success", StringComparison.OrdinalIgnoreCase)))
        {
            return "audit_success";
        }

        if (keywords.Any(keyword => keyword.Contains("Audit Failure", StringComparison.OrdinalIgnoreCase)))
        {
            return "audit_failure";
        }

        return record.Level switch
        {
            1 => "critical",
            2 => "error",
            3 => "warning",
            5 => "verbose",
            _ => "information"
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
