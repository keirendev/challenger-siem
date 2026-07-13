using System.Diagnostics;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Agent.Core.Util;

public static class ResourceMetricsSampler
{
    public static AgentResourceMetrics Sample()
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            return new AgentResourceMetrics
            {
                ObservedAt = DateTimeOffset.UtcNow,
                CpuPercent = null,
                RssBytes = process.WorkingSet64 >= 0 ? process.WorkingSet64 : null,
                ManagedMemoryBytes = GC.GetTotalMemory(forceFullCollection: false),
                Status = "partial"
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
}
