using Challenger.Siem.Contracts.V2;

namespace Challenger.Siem.LinuxAgent.Package;

public sealed record LinuxPackageJournalObservation(
    DateTimeOffset EventTime,
    string Action,
    string PackageName);

/// <summary>
/// Bounded correlation state shared by the physical journal reader and package inventory
/// observer. It contains normalized metadata only and is deliberately process-local: a restart
/// cannot make missing journal evidence look present.
/// </summary>
public sealed class LinuxPackageJournalEvidenceTracker
{
    public const int MaximumObservations = AssetInventoryPaging.MaxItemsPerSource;
    private readonly object sync = new();
    private readonly List<LinuxPackageJournalObservation> observations = [];
    private DateTimeOffset? lastBoundaryAt;
    private DateTimeOffset? lastGapAt;
    private long missingChangeCount;
    private bool overflow;

    public void Record(EventEnvelope envelope)
    {
        if (!string.Equals(envelope.SourceId, LinuxTelemetrySourceIds.PackageManagement, StringComparison.Ordinal)
            || envelope.Normalized?.Action is not { Length: > 0 } action
            || envelope.Normalized.PackageName is not { Length: > 0 } packageName
            || action is not ("install" or "update" or "remove")) return;

        lock (sync)
        {
            if (observations.Count == MaximumObservations)
            {
                observations.RemoveAt(0);
                overflow = true;
            }
            observations.Add(new(envelope.EventTime.ToUniversalTime(), action, packageName));
        }
    }

    public LinuxPackageJournalBoundaryResult ObserveBoundary(
        DateTimeOffset previousAt,
        DateTimeOffset currentAt,
        IReadOnlyCollection<(string Action, string PackageName)> changes)
    {
        lock (sync)
        {
            var start = previousAt.ToUniversalTime();
            var end = currentAt.ToUniversalTime();
            var candidates = observations
                .Where(item => item.EventTime > start && item.EventTime <= end)
                .ToList();
            var unmatched = 0;
            foreach (var change in changes)
            {
                var match = candidates.FindIndex(item =>
                    string.Equals(item.Action, change.Action, StringComparison.Ordinal)
                    && string.Equals(item.PackageName, change.PackageName, StringComparison.Ordinal));
                if (match >= 0) candidates.RemoveAt(match);
                else unmatched++;
            }

            observations.RemoveAll(item => item.EventTime <= end);
            lastBoundaryAt = end;
            var boundaryGap = overflow || unmatched > 0;
            if (boundaryGap)
            {
                lastGapAt = end;
                missingChangeCount = SaturatingAdd(missingChangeCount, unmatched);
            }
            overflow = false;
            return new(boundaryGap, unmatched, candidates.Count, lastGapAt, missingChangeCount);
        }
    }

    public LinuxPackageJournalBoundaryStatus Status()
    {
        lock (sync)
        {
            return new(lastBoundaryAt, lastGapAt, missingChangeCount,
                lastGapAt.HasValue && lastBoundaryAt.HasValue && lastGapAt >= lastBoundaryAt);
        }
    }

    private static long SaturatingAdd(long left, long right) =>
        left > long.MaxValue - right ? long.MaxValue : left + right;
}

public sealed record LinuxPackageJournalBoundaryResult(
    bool GapDetected,
    int UnmatchedChanges,
    int UnusedJournalEvents,
    DateTimeOffset? LastGapAt,
    long MissingChangeCount);

public sealed record LinuxPackageJournalBoundaryStatus(
    DateTimeOffset? LastBoundaryAt,
    DateTimeOffset? LastGapAt,
    long MissingChangeCount,
    bool ActiveGap);
