using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Challenger.Siem.Contracts.V2;

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
        var firewallAttempts = await ReadAllAsync(
            token,
            cancellationToken,
            LinuxInventoryOperation.Nftables,
            LinuxInventoryOperation.Firewalld,
            LinuxInventoryOperation.FirewalldLogging,
            LinuxInventoryOperation.Ufw,
            LinuxInventoryOperation.UfwConfiguration,
            LinuxInventoryOperation.Iptables);
        var firewallEvidence = LinuxFirewallInventoryEvidence.Evaluate(firewallAttempts.Select(FirewallProbe).ToArray());
        var firewallSnapshot = Create(
            LinuxFirewallInventoryEvidence.SnapshotType,
            agentId,
            hostname,
            collectedAt,
            SelectFirewallSnapshot(firewallAttempts, firewallEvidence));
        snapshots.Add(firewallSnapshot with { Summary = firewallEvidence.AddTo(firewallSnapshot.Summary) });
        snapshots.Add(Create("linux_ssh", agentId, hostname, collectedAt, await ReadSshAsync(token, cancellationToken)));

        var appArmor = await ReadPreferredAsync(token, cancellationToken, LinuxInventoryOperation.AppArmor, LinuxInventoryOperation.AppArmorKernel);
        var selinux = await ReadAsync(LinuxInventoryOperation.Selinux, token, cancellationToken);
        snapshots.Add(Combine("linux_mandatory_access_control", agentId, hostname, collectedAt, appArmor, selinux));
        snapshots.Add(Create("linux_secure_boot", agentId, hostname, collectedAt,
            await ReadPreferredAsync(token, cancellationToken, LinuxInventoryOperation.SecureBoot, LinuxInventoryOperation.SecureBootEfiVariable)));

        var config = await ReadAsync(LinuxInventoryOperation.AgentConfig, token, cancellationToken);
        var executable = await ReadAsync(LinuxInventoryOperation.AgentExecutable, token, cancellationToken);
        snapshots.Add(Combine("linux_agent_integrity", agentId, hostname, collectedAt, config, executable));

        if (snapshots.Count > MaxSnapshots) throw new InvalidOperationException("Inventory logical snapshot count exceeds the collection limit.");
        return PageAndBoundCollection(agentId, collectedAt, snapshots);
    }

    public int SerializedSize(string agentId, DateTimeOffset sentAt, IReadOnlyList<AssetInventorySnapshot> snapshots) =>
        JsonSerializer.SerializeToUtf8Bytes(new AssetInventoryBatchRequest { AgentId = agentId, SentAt = sentAt, Snapshots = snapshots }).Length;

    private async Task<Parsed> ReadPreferredAsync(CancellationToken token, CancellationToken caller, params LinuxInventoryOperation[] operations) =>
        (await ReadPreferredWithAttemptsAsync(token, caller, operations)).Selected;

    private async Task<Parsed> ReadSshAsync(CancellationToken token, CancellationToken caller)
    {
        var primary = await ReadAsync(LinuxInventoryOperation.SshConfig, token, caller, parse: false);
        if (primary.State != InventorySourceState.Success)
            return primary;
        var archDropIn = await ReadAsync(LinuxInventoryOperation.SshArchDropIn, token, caller, parse: false);
        if (archDropIn.State is not (InventorySourceState.Success or InventorySourceState.Unavailable))
            return archDropIn;
        if (archDropIn.State == InventorySourceState.Unavailable && archDropIn.ErrorCode != "file_missing")
            return archDropIn;
        var combined = InventorySourceResult.Success(
            string.Concat(primary.Source.Content, "\n", archDropIn.State == InventorySourceState.Success ? archDropIn.Source.Content : string.Empty),
            primary.Truncated || archDropIn.Truncated);
        var parsed = LinuxInventoryParsers.Parse(LinuxInventoryOperation.SshConfig, combined);
        return new(LinuxInventoryOperation.SshConfig, parsed.State, parsed.Items, parsed.Truncated, parsed.ErrorCode, combined);
    }

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

    private async Task<IReadOnlyList<Parsed>> ReadAllAsync(
        CancellationToken token,
        CancellationToken caller,
        params LinuxInventoryOperation[] operations)
    {
        var attempts = new List<Parsed>(operations.Length);
        foreach (var operation in operations)
        {
            attempts.Add(await ReadAsync(operation, token, caller));
        }
        return attempts;
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

    public IReadOnlyList<IReadOnlyList<AssetInventorySnapshot>> CreateRequestBatches(
        string agentId,
        DateTimeOffset sentAt,
        IReadOnlyList<AssetInventorySnapshot> snapshots)
    {
        var batches = new List<IReadOnlyList<AssetInventorySnapshot>>();
        var current = new List<AssetInventorySnapshot>();
        foreach (var snapshot in snapshots)
        {
            if (SerializedSize(agentId, sentAt, new[] { snapshot }) > maxSerializedBytes)
                throw new InvalidOperationException("One inventory page exceeds the configured serialized request budget.");
            if (current.Count == AssetInventoryPaging.MaxSnapshotsPerRequest
                || current.Count > 0 && SerializedSize(agentId, sentAt, current.Append(snapshot).ToArray()) > maxSerializedBytes)
            {
                batches.Add(current.ToArray());
                current.Clear();
            }
            current.Add(snapshot);
        }
        if (current.Count > 0) batches.Add(current.ToArray());
        return batches;
    }

    private IReadOnlyList<AssetInventorySnapshot> PageAndBoundCollection(
        string agentId,
        DateTimeOffset sentAt,
        IReadOnlyList<AssetInventorySnapshot> snapshots)
    {
        var pages = new List<AssetInventorySnapshot>();
        foreach (var snapshot in snapshots)
        {
            var generationId = ComputeGenerationId(agentId, snapshot);
            var total = Math.Min(snapshot.Items.Count, AssetInventoryPaging.MaxItemsPerSource);
            var initiallyTruncated = snapshot.Items.Count > total
                || AssetInventoryPaging.ReadBoolean(snapshot.Summary, "truncated", false);
            var chunks = new List<IReadOnlyList<InventoryItem>>();
            var current = new List<InventoryItem>(AssetInventoryPaging.MaxItemsPerPage);
            foreach (var item in snapshot.Items.Take(total))
            {
                var candidate = current.Append(item).ToArray();
                var candidatePage = BuildPage(snapshot, generationId, 1, AssetInventoryPaging.MaxPagesPerSource,
                    candidate, total, sourceTruncated: true);
                if (current.Count > 0 && SerializedSize(agentId, sentAt, [candidatePage]) > maxSerializedBytes)
                {
                    chunks.Add(current.ToArray());
                    current.Clear();
                    candidate = [item];
                    candidatePage = BuildPage(snapshot, generationId, 1, AssetInventoryPaging.MaxPagesPerSource,
                        candidate, total, sourceTruncated: true);
                }
                if (chunks.Count >= AssetInventoryPaging.MaxPagesPerSource
                    || SerializedSize(agentId, sentAt, [candidatePage]) > maxSerializedBytes) break;
                current.Add(item);
                if (current.Count == AssetInventoryPaging.MaxItemsPerPage)
                {
                    chunks.Add(current.ToArray());
                    current.Clear();
                    if (chunks.Count == AssetInventoryPaging.MaxPagesPerSource) break;
                }
            }
            if (current.Count > 0 && chunks.Count < AssetInventoryPaging.MaxPagesPerSource) chunks.Add(current.ToArray());
            if (chunks.Count == 0) chunks.Add(Array.Empty<InventoryItem>());

            var retainedChunks = chunks.ToList();
            while (true)
            {
                if (retainedChunks.Count == 0) retainedChunks.Add(Array.Empty<InventoryItem>());
                var retainedItems = retainedChunks.Sum(chunk => chunk.Count);
                var sourceTruncated = initiallyTruncated || retainedItems != total;
                var pageCount = retainedChunks.Count;
                var sourcePages = Enumerable.Range(1, pageCount)
                    .Select(pageIndex => BuildPage(
                        snapshot,
                        generationId,
                        pageIndex,
                        pageCount,
                        retainedChunks[pageIndex - 1],
                        total,
                        sourceTruncated))
                    .ToArray();
                var candidatePages = pages.Concat(sourcePages).ToArray();
                if (JsonSerializer.SerializeToUtf8Bytes(candidatePages).Length <= AssetInventoryPaging.MaxCollectionBytes)
                {
                    pages.AddRange(sourcePages);
                    break;
                }

                if (retainedChunks.Count > 1)
                {
                    retainedChunks.RemoveAt(retainedChunks.Count - 1);
                    continue;
                }
                if (retainedChunks[0].Count > 0)
                {
                    retainedChunks[0] = Array.Empty<InventoryItem>();
                    continue;
                }

                throw new InvalidOperationException("Inventory paging metadata exceeds the total in-memory collection limit.");
            }
        }

        _ = CreateRequestBatches(agentId, sentAt, pages);
        return pages;
    }

    private static AssetInventorySnapshot BuildPage(
        AssetInventorySnapshot snapshot,
        string generationId,
        int pageIndex,
        int pageCount,
        IReadOnlyList<InventoryItem> items,
        int total,
        bool sourceTruncated)
    {
        var summary = new Dictionary<string, string>(snapshot.Summary, StringComparer.OrdinalIgnoreCase)
        {
            ["generation_id"] = generationId,
            ["page_index"] = pageIndex.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["page_count"] = pageCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["page_item_count"] = items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["total_item_count"] = total.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["source_complete"] = sourceTruncated ? "false" : "true",
            ["source_truncated"] = sourceTruncated ? "true" : "false",
            ["item_count"] = items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["truncated"] = sourceTruncated ? "true" : snapshot.Summary.GetValueOrDefault("truncated", "false")
        };
        return snapshot with { Items = items.ToArray(), Summary = summary };
    }

    private static string ComputeGenerationId(string agentId, AssetInventorySnapshot snapshot)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            agent_id = agentId,
            snapshot.SnapshotType,
            collected_at = snapshot.CollectedAt.ToUniversalTime(),
            snapshot.Items,
            summary = snapshot.Summary.OrderBy(pair => pair.Key, StringComparer.Ordinal)
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
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

    private static LinuxFirewallInventoryProbe FirewallProbe(Parsed parsed)
    {
        var item = parsed.Items.FirstOrDefault(entry => entry.Kind == "firewall");
        var producer = FirewallProducer(parsed.Operation);
        var state = parsed.Truncated ? InventorySourceState.Malformed : parsed.State;
        var present = state == InventorySourceState.Success && parsed.Operation switch
        {
            LinuxInventoryOperation.Nftables or LinuxInventoryOperation.Iptables => item?.Status == "active",
            LinuxInventoryOperation.Firewalld or LinuxInventoryOperation.FirewalldLogging
                or LinuxInventoryOperation.Ufw or LinuxInventoryOperation.UfwConfiguration => item is not null,
            _ => false
        };
        var active = state == InventorySourceState.Success
            && item?.Status is "active" or "running";
        var logging = item?.Metadata.GetValueOrDefault("logging") switch
        {
            "enabled" => true,
            "disabled" => false,
            _ => (bool?)null
        };
        return new(
            producer,
            parsed.Operation != LinuxInventoryOperation.Iptables,
            state,
            present,
            active,
            logging,
            parsed.Truncated ? "firewall_inventory_output_truncated" : parsed.ErrorCode);
    }

    private static Parsed SelectFirewallSnapshot(
        IReadOnlyList<Parsed> attempts,
        LinuxFirewallInventoryEvidence evidence)
    {
        var complete = attempts.Where(attempt => !attempt.Truncated).ToArray();
        var matching = complete.FirstOrDefault(attempt =>
            string.Equals(FirewallProducer(attempt.Operation), evidence.Producer, StringComparison.Ordinal)
            && attempt.Items.Any(item => item.Kind == "firewall"));
        if (matching is not null) return matching;
        if (complete.Length > 0) return complete.OrderByDescending(attempt => StatePriority(attempt.State)).First();
        return attempts[0] with
        {
            State = InventorySourceState.Malformed,
            Items = Array.Empty<InventoryItem>(),
            ErrorCode = "firewall_inventory_output_truncated"
        };
    }

    private static string FirewallProducer(LinuxInventoryOperation operation) => operation switch
    {
        LinuxInventoryOperation.Nftables => "nftables",
        LinuxInventoryOperation.Firewalld or LinuxInventoryOperation.FirewalldLogging => "firewalld",
        LinuxInventoryOperation.Ufw or LinuxInventoryOperation.UfwConfiguration => "ufw",
        LinuxInventoryOperation.Iptables => "iptables",
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
