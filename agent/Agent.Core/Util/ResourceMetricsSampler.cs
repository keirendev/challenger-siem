using System.Diagnostics;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Agent.Core.Util;

public sealed class ResourceMetricsSampler
{
    private readonly Func<ResourceMetricSnapshot> snapshotProvider;
    private readonly object gate = new();
    private ResourceMetricSnapshot? previous;

    public ResourceMetricsSampler()
        : this(CreateProcessSnapshot)
    {
    }

    public ResourceMetricsSampler(Func<ResourceMetricSnapshot> snapshotProvider)
    {
        this.snapshotProvider = snapshotProvider;
    }

    public static ResourceMetricsSampler Shared { get; } = new();

    public static AgentResourceMetrics Sample() => Shared.SampleNow();

    public AgentResourceMetrics SampleNow()
    {
        try
        {
            var current = snapshotProvider();
            decimal? cpuPercent = null;
            lock (gate)
            {
                if (previous is { } prior)
                {
                    var elapsedMilliseconds = (current.ObservedAt - prior.ObservedAt).TotalMilliseconds;
                    var cpuMilliseconds = (current.TotalProcessorTime - prior.TotalProcessorTime).TotalMilliseconds;
                    if (elapsedMilliseconds > 0 && cpuMilliseconds >= 0 && current.ProcessorCount > 0)
                    {
                        var rawPercent = (decimal)(cpuMilliseconds / elapsedMilliseconds / current.ProcessorCount * 100d);
                        cpuPercent = Math.Round(Math.Clamp(rawPercent, 0m, 100m), 3, MidpointRounding.AwayFromZero);
                    }
                }

                previous = current;
            }

            return new AgentResourceMetrics
            {
                ObservedAt = current.ObservedAt,
                CpuPercent = cpuPercent,
                RssBytes = current.RssBytes,
                ManagedMemoryBytes = current.ManagedMemoryBytes,
                Status = cpuPercent.HasValue ? "observed" : "partial"
            };
        }
        catch
        {
            return new AgentResourceMetrics
            {
                ObservedAt = DateTimeOffset.UtcNow,
                CpuPercent = null,
                RssBytes = null,
                ManagedMemoryBytes = null,
                Status = "unknown"
            };
        }
    }

    private static ResourceMetricSnapshot CreateProcessSnapshot()
    {
        using var process = Process.GetCurrentProcess();
        return new ResourceMetricSnapshot(
            DateTimeOffset.UtcNow,
            process.TotalProcessorTime,
            Math.Max(1, Environment.ProcessorCount),
            process.WorkingSet64 >= 0 ? process.WorkingSet64 : null,
            GC.GetTotalMemory(forceFullCollection: false));
    }
}

public readonly record struct ResourceMetricSnapshot(
    DateTimeOffset ObservedAt,
    TimeSpan TotalProcessorTime,
    int ProcessorCount,
    long? RssBytes,
    long? ManagedMemoryBytes);
