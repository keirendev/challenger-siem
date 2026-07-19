using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Pages.Agents;

public sealed record InventoryChangeReview(string ChangeType, string Kind, string DisplayName, string Status, string MetadataSummary);

public sealed record InventorySnapshotReview(
    string SnapshotType,
    string Status,
    DateTimeOffset? CurrentCollectedAt,
    DateTimeOffset? PreviousCollectedAt,
    HostTimezoneMetadata? HostTimezone,
    int CurrentItemCount,
    int PreviousItemCount,
    int AddedCount,
    int RemovedCount,
    int ChangedCount,
    IReadOnlyList<InventoryChangeReview> Changes,
    string RedactionLabel);

public sealed class DetailModel(
    SourceHealthRepository sourceHealth,
    TelemetryCoverageRepository telemetryCoverage,
    AssetInventoryRepository inventoryRepository,
    EventRepository eventRepository,
    IOptions<ManagedRetentionOptions> retentionOptions) : PageModel
{
    public string? AgentId { get; private set; }
    public WindowsCoverageLevel TargetLevel { get; private set; } = WindowsCoverageLevel.L4;
    public IReadOnlyList<WindowsCoverageLevel> TargetLevels { get; } = new[] { WindowsCoverageLevel.L1, WindowsCoverageLevel.L2, WindowsCoverageLevel.L3, WindowsCoverageLevel.L4 };
    public CoverageSummary? Summary { get; private set; }
    public AgentTelemetryCoverage? Coverage { get; private set; }
    public IReadOnlyList<SourceTelemetryCoverage> Sources { get; private set; } = Array.Empty<SourceTelemetryCoverage>();
    public IReadOnlyList<InventorySnapshotReview> InventorySnapshots { get; private set; } = Array.Empty<InventorySnapshotReview>();
    public ManagedStorageAccounting? StorageAccounting { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync(
        [FromQuery(Name = "agent_id")] string? agentId,
        [FromQuery(Name = "target_level")] string? targetLevel,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(agentId))
        {
            ErrorMessage = "An agent_id query value is required.";
            return Page();
        }

        AgentId = agentId;
        TargetLevel = ParseTargetLevel(targetLevel);
        try
        {
            var response = await sourceHealth.SearchAsync(agentId, TargetLevel, cancellationToken);
            Summary = response.Summaries.FirstOrDefault();
            var coverageResponse = await telemetryCoverage.AssessAsync(agentId, TargetLevel, 24, cancellationToken);
            Coverage = coverageResponse.Agents.FirstOrDefault();
            Sources = Coverage?.Sources ?? response.Sources.Select(source => new SourceTelemetryCoverage
            {
                SourceId = source.SourceId,
                DisplayName = source.DisplayName,
                Channel = source.Channel ?? string.Empty,
                Platform = source.Platform,
                SourceKind = source.SourceKind,
                SourceNamespace = source.SourceNamespace,
                Applicability = source.Applicability,
                ApplicabilityReason = source.ApplicabilityReason,
                Requirement = source.Requirement,
                ApplicableRoles = source.ApplicableRoles,
                PrerequisiteStatuses = source.PrerequisiteStatuses,
                EventFamilyStatuses = source.EventFamilyStatuses,
                CoverageLevel = source.CoverageLevel,
                Required = source.Required,
                Enabled = source.Enabled,
                Status = source.Status,
                LastEventTime = source.LastEventTime,
                ObservedAt = source.ObservedAt,
                HostTimezone = source.HostTimezone ?? Summary?.HostTimezone,
                SourceVersion = source.SourceVersion,
                ConfigHash = source.ConfigHash,
                Details = source.Details,
                Reason = source.ErrorMessage ?? source.ErrorCode ?? string.Empty
            }).ToArray();
            var role = OperatorAuthorization.Role(User) ?? OperatorRoles.Viewer;
            InventorySnapshots = BuildInventorySnapshotReviews(
                await inventoryRepository.SearchAsync(agentId, null, cancellationToken),
                role);
            StorageAccounting = await eventRepository.GetManagedStorageAccountingAsync(
                retentionOptions.Value.ManagedCapacityBytes,
                cancellationToken,
                retentionOptions.Value.TargetRetentionDays);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "Source health could not be loaded. Confirm the database schema has been applied.";
        }

        return Page();
    }

    public static string CapacityState(decimal? usedPercent) => usedPercent switch
    {
        null => "unknown",
        >= 100 => "over_capacity",
        >= 95 => "critical_95",
        >= 85 => "warning_85",
        >= 70 => "warning_70",
        _ => "normal"
    };

    public static string CapacityGuidance(string state) => state switch
    {
        "over_capacity" => "100% capacity reached: pause rollout expansion, run retention dry-run, and verify queue drain before treating telemetry as complete.",
        "critical_95" => "95% critical capacity: prioritize retention dry-run and investigate high-volume sources.",
        "warning_85" => "85% warning: review retention status, source volume, and queue growth before expansion.",
        "warning_70" => "70% warning: capacity is approaching the managed threshold; monitor trend and planned retention.",
        "unknown" => "Capacity is unknown because the agent did not report queue byte usage.",
        _ => "Capacity is below the 70% warning threshold."
    };

    public static string SourceStateGuidance(SourceTelemetryCoverage source) => source.Status switch
    {
        SourceHealthStatuses.Missing => "Expected telemetry is absent. Verify agent/source configuration and prerequisites through an approved runbook; do not treat absence as clean evidence.",
        SourceHealthStatuses.Unsupported when !IsMandatoryForCoverage(source) => "This optional capability is not supported by the current collector set. It remains visible for capability review but does not degrade aggregate health or create a completeness gap.",
        SourceHealthStatuses.Unsupported => "This required source is not supported by the current collector set. Track it as a visibility gap unless a future approved collector is added.",
        SourceHealthStatuses.NotApplicable => "The declared platform or role makes this source not applicable. Keep the reason visible for review.",
        SourceHealthStatuses.Excepted => "An approved coverage exception is active. Review exception scope and expiry outside this page.",
        SourceHealthStatuses.Disabled => "The source is explicitly disabled. Follow configuration/change-control runbooks; this UI does not enable it.",
        SourceHealthStatuses.PermissionDenied => "Access was denied. Review least-privilege prerequisites; this UI does not change host permissions.",
        SourceHealthStatuses.Stale => "Last evidence is older than expected. Compare heartbeat, queue, and source timestamps before assuming quiet activity.",
        SourceHealthStatuses.Degraded => source.TransitionState == HealthTransitionStates.Degraded ? "Source is degraded and may be throttled. Review queue pressure and collector limits." : "Source is degraded or applicability is uncertain. Treat findings as partial.",
        SourceHealthStatuses.Error => "Collector or processing error reported. Use safe diagnostics; do not clear logs or mutate policy from the console.",
        _ when source.RecentEventCount == 0 && SourceHealthRules.IsSuccessfulPollingSource(source.SourceId) => "A current successful bounded source observation establishes readiness even when the source produced no new event.",
        _ => source.RecentEventCount == 0 ? "Health is reported but no recent events were observed in the lookback; evidence may be quiet or incomplete." : "Recent source evidence is present."
    };

    public static string SourceStatusBadgeClass(SourceTelemetryCoverage source)
    {
        if (source.Status is SourceHealthStatuses.Healthy or SourceHealthStatuses.NotApplicable or SourceHealthStatuses.Excepted)
        {
            return "ok";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Unsupported, StringComparison.OrdinalIgnoreCase)
            && !IsMandatoryForCoverage(source))
        {
            return "informational";
        }

        return source.Status is SourceHealthStatuses.Stale or SourceHealthStatuses.Missing or SourceHealthStatuses.Degraded or SourceHealthStatuses.Disabled
            ? "warning"
            : "danger";
    }

    private static bool IsMandatoryForCoverage(SourceTelemetryCoverage source) => source.Requirement switch
    {
        SourceRequirementKinds.Mandatory => true,
        SourceRequirementKinds.RoleSpecific => source.Applicability == SourceApplicabilityStatuses.Applicable,
        SourceRequirementKinds.Optional => false,
        _ => source.Required
    };

    private static IReadOnlyList<InventorySnapshotReview> BuildInventorySnapshotReviews(
        IReadOnlyList<AssetInventorySnapshot> snapshots,
        string role)
    {
        var showProtectedValues = string.Equals(role, OperatorRoles.Admin, StringComparison.OrdinalIgnoreCase);
        return snapshots
            .GroupBy(snapshot => snapshot.SnapshotType, StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Take(20)
            .Select(group =>
            {
                var ordered = group.OrderByDescending(snapshot => snapshot.CollectedAt).Take(2).ToArray();
                var current = ordered[0];
                var previous = ordered.Length > 1 ? ordered[1] : null;
                var changes = BuildChanges(current, previous, showProtectedValues);
                return new InventorySnapshotReview(
                    current.SnapshotType,
                    current.Summary.TryGetValue("state", out var state) ? state : "success",
                    current.CollectedAt,
                    previous?.CollectedAt,
                    current.HostTimezone,
                    current.Items.Count,
                    previous?.Items.Count ?? 0,
                    changes.Count(change => change.ChangeType == "added"),
                    changes.Count(change => change.ChangeType == "removed"),
                    changes.Count(change => change.ChangeType == "changed"),
                    changes.Take(8).ToArray(),
                    showProtectedValues ? "admin view: bounded synthetic/raw inventory item labels may be shown" : "role-redacted: item identities and metadata values are withheld");
            })
            .ToArray();
    }

    private static IReadOnlyList<InventoryChangeReview> BuildChanges(
        AssetInventorySnapshot current,
        AssetInventorySnapshot? previous,
        bool showProtectedValues)
    {
        if (previous is null)
        {
            return current.Items.Take(8)
                .Select(item => ToChange("added", item, showProtectedValues))
                .ToArray();
        }

        var currentByKey = current.Items.GroupBy(ItemKey, StringComparer.OrdinalIgnoreCase).ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var previousByKey = previous.Items.GroupBy(ItemKey, StringComparer.OrdinalIgnoreCase).ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var changes = new List<InventoryChangeReview>();
        foreach (var key in currentByKey.Keys.Except(previousByKey.Keys, StringComparer.OrdinalIgnoreCase))
        {
            changes.Add(ToChange("added", currentByKey[key], showProtectedValues));
        }
        foreach (var key in previousByKey.Keys.Except(currentByKey.Keys, StringComparer.OrdinalIgnoreCase))
        {
            changes.Add(ToChange("removed", previousByKey[key], showProtectedValues));
        }
        foreach (var key in currentByKey.Keys.Intersect(previousByKey.Keys, StringComparer.OrdinalIgnoreCase))
        {
            if (!ItemFingerprint(currentByKey[key]).Equals(ItemFingerprint(previousByKey[key]), StringComparison.Ordinal))
            {
                changes.Add(ToChange("changed", currentByKey[key], showProtectedValues));
            }
        }

        return changes
            .OrderBy(change => change.ChangeType, StringComparer.Ordinal)
            .ThenBy(change => change.Kind, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static InventoryChangeReview ToChange(string changeType, InventoryItem item, bool showProtectedValues) => new(
        changeType,
        item.Kind,
        showProtectedValues ? (string.IsNullOrWhiteSpace(item.Name) ? item.Kind : item.Name) : "redacted inventory item",
        item.Status ?? "observed",
        showProtectedValues ? string.Join(", ", item.Metadata.Take(4).Select(pair => $"{pair.Key}={pair.Value}")) : $"{item.Metadata.Count} metadata field(s) redacted");

    private static string ItemKey(InventoryItem item) => string.Join("|", item.Kind, item.Name, item.Identity ?? string.Empty);

    private static string ItemFingerprint(InventoryItem item) => JsonSerializer.Serialize(new { item.Status, item.Metadata }, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private static WindowsCoverageLevel ParseTargetLevel(string? targetLevel)
    {
        return Enum.TryParse<WindowsCoverageLevel>(targetLevel, ignoreCase: true, out var parsed) && parsed is >= WindowsCoverageLevel.L1 and <= WindowsCoverageLevel.L4
            ? parsed
            : WindowsCoverageLevel.L4;
    }
}
