using System.Text.Json;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Inventory;

public interface ILinuxInventoryCollector
{
    Task<IReadOnlyList<AssetInventorySnapshot>> CollectAsync(string agentId, string hostname, CancellationToken cancellationToken);
}

public sealed class LinuxInventory(
    ILinuxInventorySource source,
    TimeProvider timeProvider,
    TimeSpan collectionTimeout,
    int maxSerializedBytes) : ILinuxInventoryCollector
{
    public const int MaxSnapshots = 20;
    public const int DefaultMaxSerializedBytes = 256 * 1024;
    public const int MinimumSerializedBytes = 64 * 1024;
    public const int MaximumSerializedBytes = 512 * 1024;

    public async Task<IReadOnlyList<AssetInventorySnapshot>> CollectAsync(string agentId, string hostname, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentException.ThrowIfNullOrWhiteSpace(hostname);
        if (maxSerializedBytes is < MinimumSerializedBytes or > MaximumSerializedBytes)
            throw new InvalidOperationException("Inventory serialized size limit is outside the supported range.");

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(collectionTimeout);
        var token = deadline.Token;
        var collectedAt = timeProvider.GetUtcNow();
        var snapshots = new List<AssetInventorySnapshot>(15);

        var os = await ReadPreferredAsync(token, cancellationToken, LinuxInventoryOperation.OsReleaseEtc, LinuxInventoryOperation.OsReleaseUsrLib);
        var kernel = await ReadAsync(LinuxInventoryOperation.Kernel, token, cancellationToken);
        snapshots.Add(Combine("linux_host_identity", agentId, hostname, collectedAt, os, kernel));

        snapshots.Add(Create("linux_users", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.Users, token, cancellationToken)));
        snapshots.Add(Create("linux_groups", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.Groups, token, cancellationToken)));

        var init = await ReadAsync(LinuxInventoryOperation.InitSystem, token, cancellationToken, parse: false);
        if (init.Source.State == InventorySourceState.Success && LinuxInventoryParsers.IsNonSystemd(init.Source))
        {
            var notApplicable = new Parsed(init.Operation, InventorySourceState.NotApplicable, Array.Empty<InventoryItem>(), false, "non_systemd", init.Source);
            snapshots.Add(Create("linux_services", agentId, hostname, collectedAt, notApplicable));
            snapshots.Add(Create("linux_units", agentId, hostname, collectedAt, notApplicable));
            snapshots.Add(Create("linux_timers", agentId, hostname, collectedAt, notApplicable));
        }
        else if (init.Source.State != InventorySourceState.Success)
        {
            var unavailable = new Parsed(init.Operation, init.Source.State, Array.Empty<InventoryItem>(), init.Source.Truncated, init.Source.ErrorCode, init.Source);
            snapshots.Add(Create("linux_services", agentId, hostname, collectedAt, unavailable));
            snapshots.Add(Create("linux_units", agentId, hostname, collectedAt, unavailable));
            snapshots.Add(Create("linux_timers", agentId, hostname, collectedAt, unavailable));
        }
        else
        {
            snapshots.Add(Create("linux_services", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.Services, token, cancellationToken)));
            snapshots.Add(Create("linux_units", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.Units, token, cancellationToken)));
            snapshots.Add(Create("linux_timers", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.Timers, token, cancellationToken)));
        }

        var packageInventory = await ReadPreferredWithAttemptsAsync(
            token,
            cancellationToken,
            LinuxInventoryOperation.DpkgPackages,
            LinuxInventoryOperation.RpmPackages,
            LinuxInventoryOperation.PacmanPackages);
        var packageEvidence = LinuxPackageManagementInventoryEvidence.Evaluate(
            DistributionId(os),
            packageInventory.Attempts.Select(item => new LinuxPackageManagerInventoryProbe(
                PackageProducer(item.Operation),
                item.State,
                item.ErrorCode)).ToArray());
        var packageSnapshot = Create("linux_packages", agentId, hostname, collectedAt, packageInventory.Selected);
        snapshots.Add(packageSnapshot with { Summary = packageEvidence.AddTo(packageSnapshot.Summary) });
        snapshots.Add(Create("linux_available_updates", agentId, hostname, collectedAt,
            await ReadPreferredAsync(token, cancellationToken, LinuxInventoryOperation.AptUpdates, LinuxInventoryOperation.DnfUpdates, LinuxInventoryOperation.PacmanUpdates)));
        snapshots.Add(Create("linux_interfaces", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.Interfaces, token, cancellationToken)));
        snapshots.Add(Create("linux_listeners", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.Listeners, token, cancellationToken)));
        snapshots.Add(Create("linux_mounts", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.Mounts, token, cancellationToken)));
        snapshots.Add(Create("linux_firewall", agentId, hostname, collectedAt,
            await ReadPreferredAsync(token, cancellationToken, LinuxInventoryOperation.Nftables, LinuxInventoryOperation.Firewalld, LinuxInventoryOperation.Ufw)));
        snapshots.Add(Create("linux_ssh", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.SshConfig, token, cancellationToken)));

        var appArmor = await ReadAsync(LinuxInventoryOperation.AppArmor, token, cancellationToken);
        var selinux = await ReadAsync(LinuxInventoryOperation.Selinux, token, cancellationToken);
        snapshots.Add(Combine("linux_mandatory_access_control", agentId, hostname, collectedAt, appArmor, selinux));
        snapshots.Add(Create("linux_secure_boot", agentId, hostname, collectedAt, await ReadAsync(LinuxInventoryOperation.SecureBoot, token, cancellationToken)));

        var config = await ReadAsync(LinuxInventoryOperation.AgentConfig, token, cancellationToken);
        var executable = await ReadAsync(LinuxInventoryOperation.AgentExecutable, token, cancellationToken);
        snapshots.Add(Combine("linux_agent_integrity", agentId, hostname, collectedAt, config, executable));

        if (snapshots.Count > MaxSnapshots) throw new InvalidOperationException("Inventory snapshot count exceeds the contract limit.");
        return EnforceSerializedBudget(agentId, collectedAt, snapshots);
    }

    public int SerializedSize(string agentId, DateTimeOffset sentAt, IReadOnlyList<AssetInventorySnapshot> snapshots) =>
        JsonSerializer.SerializeToUtf8Bytes(new AssetInventoryBatchRequest { AgentId = agentId, SentAt = sentAt, Snapshots = snapshots }).Length;

    private async Task<Parsed> ReadPreferredAsync(CancellationToken token, CancellationToken caller, params LinuxInventoryOperation[] operations) =>
        (await ReadPreferredWithAttemptsAsync(token, caller, operations)).Selected;

    private async Task<PreferredRead> ReadPreferredWithAttemptsAsync(
        CancellationToken token,
        CancellationToken caller,
        params LinuxInventoryOperation[] operations)
    {
        Parsed? strongest = null;
        var attempts = new List<Parsed>(operations.Length);
        foreach (var operation in operations)
        {
            var result = await ReadAsync(operation, token, caller);
            attempts.Add(result);
            if (result.State == InventorySourceState.Success) return new(result, attempts);
            if (result.State == InventorySourceState.Malformed && result.ErrorCode != "file_not_regular") return new(result, attempts);
            if (strongest is null || StatePriority(result.State) > StatePriority(strongest.State)) strongest = result;
        }
        return new(strongest!, attempts);
    }

    private async Task<Parsed> ReadAsync(LinuxInventoryOperation operation, CancellationToken token, CancellationToken caller, bool parse = true)
    {
        InventorySourceResult result;
        try { result = await source.ReadAsync(operation, token); }
        catch (OperationCanceledException) when (!caller.IsCancellationRequested)
        {
            result = new(InventorySourceState.Timeout, "collection_deadline");
        }
        if (!parse) return new(operation, result.State, Array.Empty<InventoryItem>(), result.Truncated, result.ErrorCode, result);
        var parsed = LinuxInventoryParsers.Parse(operation, result);
        return new(operation, parsed.State, parsed.Items, parsed.Truncated, parsed.ErrorCode, result);
    }

    private static AssetInventorySnapshot Create(string type, string agentId, string hostname, DateTimeOffset collectedAt, Parsed parsed)
    {
        return new AssetInventorySnapshot
        {
            AgentId = agentId,
            Hostname = hostname,
            SnapshotType = type,
            CollectedAt = collectedAt,
            Items = parsed.Items,
            Summary = Summary(parsed.State, parsed.ErrorCode, parsed.Items.Count, parsed.Truncated)
        };
    }

    private static AssetInventorySnapshot Combine(string type, string agentId, string hostname, DateTimeOffset collectedAt, params Parsed[] sources)
    {
        var items = sources.SelectMany(x => x.Items).OrderBy(x => x.Kind, StringComparer.Ordinal).ThenBy(x => x.Name, StringComparer.Ordinal)
            .Take(LinuxInventoryParsers.MaxItemsPerSnapshot).ToArray();
        var state = sources.Any(x => x.State == InventorySourceState.Success)
            ? InventorySourceState.Success
            : sources.OrderByDescending(x => StatePriority(x.State)).First().State;
        var truncated = sources.Any(x => x.Truncated) || sources.Sum(x => x.Items.Count) > items.Length;
        var error = state == InventorySourceState.Success ? "none" : sources.OrderByDescending(x => StatePriority(x.State)).First().ErrorCode;
        var summary = Summary(state, error, items.Length, truncated);
        for (var index = 0; index < sources.Length; index++) summary[$"source_{index + 1}_state"] = StateName(sources[index].State);
        return new AssetInventorySnapshot { AgentId = agentId, Hostname = hostname, SnapshotType = type, CollectedAt = collectedAt, Items = items, Summary = summary };
    }

    private IReadOnlyList<AssetInventorySnapshot> EnforceSerializedBudget(string agentId, DateTimeOffset sentAt, List<AssetInventorySnapshot> snapshots)
    {
        var bounded = snapshots.ToArray();
        for (var snapshotIndex = bounded.Length - 1; snapshotIndex >= 0 && SerializedSize(agentId, sentAt, bounded) > maxSerializedBytes; snapshotIndex--)
        {
            while (bounded[snapshotIndex].Items.Count > 0 && SerializedSize(agentId, sentAt, bounded) > maxSerializedBytes)
            {
                var retainedItems = bounded[snapshotIndex].Items.Take(bounded[snapshotIndex].Items.Count - 1).ToArray();
                var summary = new Dictionary<string, string>(bounded[snapshotIndex].Summary, StringComparer.Ordinal)
                {
                    ["truncated"] = "true",
                    ["payload_budget_truncated"] = "true",
                    ["original_item_count"] = bounded[snapshotIndex].Summary.GetValueOrDefault("original_item_count", bounded[snapshotIndex].Summary["item_count"]),
                    ["item_count"] = retainedItems.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
                };
                bounded[snapshotIndex] = bounded[snapshotIndex] with { Items = retainedItems, Summary = summary };
            }
        }
        if (SerializedSize(agentId, sentAt, bounded) > maxSerializedBytes)
            throw new InvalidOperationException("Inventory metadata exceeds the configured serialized size budget.");
        return bounded;
    }

    private static Dictionary<string, string> Summary(InventorySourceState state, string errorCode, int count, bool truncated) => new(StringComparer.Ordinal)
    {
        ["state"] = StateName(state),
        ["error_code"] = errorCode,
        ["item_count"] = count.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["truncated"] = truncated ? "true" : "false"
    };

    private static int StatePriority(InventorySourceState state) => state switch
    {
        InventorySourceState.PermissionDenied => 6,
        InventorySourceState.Timeout => 5,
        InventorySourceState.Malformed => 4,
        InventorySourceState.NotApplicable => 3,
        InventorySourceState.Unavailable => 2,
        _ => 1
    };

    private static string StateName(InventorySourceState state) => state switch
    {
        InventorySourceState.Success => "success",
        InventorySourceState.Unavailable => "unavailable",
        InventorySourceState.NotApplicable => "not_applicable",
        InventorySourceState.PermissionDenied => "permission_denied",
        InventorySourceState.Timeout => "timeout",
        InventorySourceState.Malformed => "malformed",
        _ => throw new ArgumentOutOfRangeException(nameof(state))
    };

    private static string? DistributionId(Parsed os) => os.Items
        .FirstOrDefault(item => item.Kind == "operating_system")?
        .Metadata.GetValueOrDefault("distribution_id");

    private static string PackageProducer(LinuxInventoryOperation operation) => operation switch
    {
        LinuxInventoryOperation.DpkgPackages => "dpkg",
        LinuxInventoryOperation.RpmPackages => "rpm",
        LinuxInventoryOperation.PacmanPackages => "pacman",
        _ => "unknown"
    };

    private sealed record PreferredRead(Parsed Selected, IReadOnlyList<Parsed> Attempts);
    private sealed record Parsed(
        LinuxInventoryOperation Operation,
        InventorySourceState State,
        IReadOnlyList<InventoryItem> Items,
        bool Truncated,
        string ErrorCode,
        InventorySourceResult Source);
}
