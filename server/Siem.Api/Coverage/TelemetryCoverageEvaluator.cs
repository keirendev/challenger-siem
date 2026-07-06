using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Coverage;

public static class TelemetryCoverageEvaluator
{
    public const string StatusSatisfied = "satisfied";
    public const string StatusPartiallySatisfied = "partially_satisfied";
    public const string StatusMissingPrerequisites = "missing_prerequisites";
    public const string StatusUnknown = "unknown";
    public const string StatusExcepted = "excepted";

    private static readonly HashSet<string> CoveredSourceStatuses = new(StringComparer.OrdinalIgnoreCase)
    {
        SourceHealthStatuses.Healthy,
        SourceHealthStatuses.Excepted,
        SourceHealthStatuses.NotApplicable
    };

    public static IReadOnlyList<SourceHealthReport> MergeExpectedSources(
        IReadOnlyList<SourceHealthReport> reportedSources,
        WindowsCoverageLevel targetLevel,
        IReadOnlySet<string> exceptedSourceIds,
        DateTimeOffset now)
    {
        var reportedBySource = reportedSources
            .GroupBy(source => source.SourceId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var merged = new List<SourceHealthReport>();

        foreach (var expected in WindowsTelemetrySourceCatalog.ExpectedFor(targetLevel))
        {
            if (reportedBySource.TryGetValue(expected.SourceId, out var reported))
            {
                var status = SourceHealthRules.EffectiveStatus(reported, now);
                var reportedExcepted = IsExcepted(expected.SourceId, exceptedSourceIds);
                if (reportedExcepted && IsGapStatus(status))
                {
                    status = SourceHealthStatuses.Excepted;
                }

                merged.Add(reported with
                {
                    Status = status,
                    Required = expected.Required,
                    Enabled = reported.Enabled,
                    Details = MergeDetails(reported.Details, expected, reported: true, reportedExcepted)
                });
                continue;
            }

            var missingExcepted = IsExcepted(expected.SourceId, exceptedSourceIds);
            merged.Add(new SourceHealthReport
            {
                SourceId = expected.SourceId,
                DisplayName = expected.DisplayName,
                Channel = expected.Channel,
                CoverageLevel = expected.CoverageLevel,
                Status = missingExcepted ? SourceHealthStatuses.Excepted : SourceHealthStatuses.Missing,
                Required = expected.Required,
                Enabled = expected.EnabledByDefault,
                ErrorCode = missingExcepted ? null : "expected_source_not_reported",
                ErrorMessage = missingExcepted ? null : "Expected source has not been reported by agent source-health heartbeat.",
                Details = MergeDetails(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), expected, reported: false, missingExcepted)
            });
        }

        foreach (var custom in reportedSources.Where(source => !merged.Any(item => string.Equals(item.SourceId, source.SourceId, StringComparison.OrdinalIgnoreCase))))
        {
            merged.Add(custom with { Status = SourceHealthRules.EffectiveStatus(custom, now) });
        }

        return merged
            .OrderBy(source => source.CoverageLevel)
            .ThenByDescending(source => source.Required)
            .ThenBy(source => source.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static CoverageSummary RecalculateSummary(
        CoverageSummary summary,
        IReadOnlyList<SourceHealthReport> sources,
        WindowsCoverageLevel targetLevel)
    {
        var missingMandatory = sources.Count(source => source.Required && source.Status is SourceHealthStatuses.Missing or SourceHealthStatuses.Disabled);
        var stale = sources.Count(source => string.Equals(source.Status, SourceHealthStatuses.Stale, StringComparison.OrdinalIgnoreCase));
        var error = sources.Count(source => string.Equals(source.Status, SourceHealthStatuses.Error, StringComparison.OrdinalIgnoreCase));
        var currentLevel = CalculateCurrentLevel(sources, targetLevel);
        var overallStatus = CalculateOverallStatus(sources);

        return summary with
        {
            TargetLevel = targetLevel,
            CurrentLevel = currentLevel,
            OverallStatus = overallStatus,
            MissingMandatorySources = missingMandatory,
            StaleSources = stale,
            ErrorSources = error
        };
    }

    public static CoverageSummary CreateSummary(
        string agentId,
        string hostname,
        int queueDepth,
        DateTimeOffset? lastHeartbeatTime,
        IReadOnlyList<SourceHealthReport> sources,
        WindowsCoverageLevel targetLevel)
    {
        return RecalculateSummary(new CoverageSummary
        {
            AgentId = agentId,
            Hostname = hostname,
            TargetLevel = targetLevel,
            QueueDepth = queueDepth,
            LastHeartbeatTime = lastHeartbeatTime
        }, sources, targetLevel);
    }

    public static WindowsCoverageLevel CalculateCurrentLevel(IReadOnlyList<SourceHealthReport> sources, WindowsCoverageLevel targetLevel)
    {
        var current = WindowsCoverageLevel.L0;
        foreach (var level in new[] { WindowsCoverageLevel.L1, WindowsCoverageLevel.L2, WindowsCoverageLevel.L3, WindowsCoverageLevel.L4 })
        {
            if (level > targetLevel)
            {
                break;
            }

            var required = WindowsTelemetrySourceCatalog.ExpectedFor(level, includeOptional: false)
                .Where(source => source.CoverageLevel <= level)
                .ToArray();
            if (required.Length == 0)
            {
                continue;
            }

            var levelMet = required.All(expected => sources.Any(source =>
                string.Equals(source.SourceId, expected.SourceId, StringComparison.OrdinalIgnoreCase)
                && CoveredSourceStatuses.Contains(source.Status)));
            if (!levelMet)
            {
                break;
            }

            current = level;
        }

        return current;
    }

    public static string CalculateOverallStatus(IReadOnlyList<SourceHealthReport> sources)
    {
        if (sources.Count == 0)
        {
            return SourceHealthStatuses.Missing;
        }

        if (sources.Any(source => string.Equals(source.Status, SourceHealthStatuses.Error, StringComparison.OrdinalIgnoreCase)))
        {
            return SourceHealthStatuses.Error;
        }

        if (sources.Any(source => source.Required && (string.Equals(source.Status, SourceHealthStatuses.Missing, StringComparison.OrdinalIgnoreCase)
            || string.Equals(source.Status, SourceHealthStatuses.Disabled, StringComparison.OrdinalIgnoreCase))))
        {
            return SourceHealthStatuses.Missing;
        }

        if (sources.Any(source => string.Equals(source.Status, SourceHealthStatuses.Stale, StringComparison.OrdinalIgnoreCase)))
        {
            return SourceHealthStatuses.Stale;
        }

        return SourceHealthStatuses.Healthy;
    }

    public static IReadOnlyList<DetectionPrerequisiteTelemetryStatus> EvaluateDetectionPrerequisites(
        IReadOnlyList<DetectionRuleMetadata> rules,
        IReadOnlyList<SourceTelemetryCoverage> sources,
        IReadOnlyDictionary<string, InventoryTelemetryStatus> inventoryByType,
        WindowsCoverageLevel targetLevel)
    {
        return rules
            .OrderBy(rule => rule.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase)
            .Select(rule => EvaluateDetectionPrerequisite(rule, sources, inventoryByType, targetLevel))
            .ToArray();
    }

    private static DetectionPrerequisiteTelemetryStatus EvaluateDetectionPrerequisite(
        DetectionRuleMetadata rule,
        IReadOnlyList<SourceTelemetryCoverage> sources,
        IReadOnlyDictionary<string, InventoryTelemetryStatus> inventoryByType,
        WindowsCoverageLevel targetLevel)
    {
        var profile = DetectionPrerequisiteCatalog.ForRule(rule.RuleId);
        var requiredSources = rule.RequiredSources;
        var inScopeRequiredSources = requiredSources
            .Where(source => SourceAppliesToTargetLevel(source, targetLevel))
            .ToArray();
        if (rule.Enabled && requiredSources.Count > 0 && inScopeRequiredSources.Length == 0)
        {
            return new DetectionPrerequisiteTelemetryStatus
            {
                RuleId = rule.RuleId,
                Name = rule.Name,
                Severity = rule.Severity,
                Enabled = rule.Enabled,
                Status = StatusExcepted,
                RequiredSources = requiredSources,
                RequiredFields = rule.RequiredFields,
                RequiredEventIds = profile.RequiredEventIds,
                RequiredEventCategories = profile.RequiredEventCategories,
                RequiredEventActions = profile.RequiredEventActions,
                AuditPolicyRequirements = profile.AuditPolicyRequirements,
                InventoryRequirements = profile.InventoryRequirements,
                OptionalSources = profile.OptionalSources,
                Reason = $"Rule requires source coverage above target level {targetLevel}; not counted as an L2 prerequisite gap."
            };
        }

        var healthySources = new List<string>();
        var staleSources = new List<string>();
        var missingSources = new List<string>();
        var recentEventSources = new List<string>();

        foreach (var requiredSource in inScopeRequiredSources)
        {
            if (string.Equals(requiredSource, "source-health", StringComparison.OrdinalIgnoreCase))
            {
                if (sources.Any(source => source.Reported))
                {
                    healthySources.Add(requiredSource);
                    recentEventSources.Add(requiredSource);
                }
                else
                {
                    missingSources.Add(requiredSource);
                }

                continue;
            }

            var matching = sources
                .Where(source => WindowsTelemetrySourceCatalog.SourceMatches(requiredSource, source.SourceId))
                .ToArray();
            if (matching.Length == 0)
            {
                missingSources.Add(requiredSource);
                continue;
            }

            if (matching.Any(source => string.Equals(source.Status, SourceHealthStatuses.Stale, StringComparison.OrdinalIgnoreCase)))
            {
                staleSources.Add(requiredSource);
            }

            if (matching.Any(source => CoveredSourceStatuses.Contains(source.Status)))
            {
                healthySources.Add(requiredSource);
            }
            else if (!staleSources.Contains(requiredSource, StringComparer.OrdinalIgnoreCase))
            {
                missingSources.Add(requiredSource);
            }

            if (matching.Any(source => source.RecentEventCount > 0))
            {
                recentEventSources.Add(requiredSource);
            }
        }

        var missingInventory = profile.InventoryRequirements
            .Where(requirement => !inventoryByType.TryGetValue(requirement, out var inventory)
                || string.Equals(inventory.Status, SourceHealthStatuses.Missing, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var staleInventory = profile.InventoryRequirements
            .Where(requirement => inventoryByType.TryGetValue(requirement, out var inventory)
                && string.Equals(inventory.Status, SourceHealthStatuses.Stale, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        var status = DetermineDetectionStatus(rule, inScopeRequiredSources, healthySources, recentEventSources, missingSources, staleSources, missingInventory, staleInventory);
        var reason = BuildDetectionReason(status, inScopeRequiredSources, healthySources, recentEventSources, missingSources, staleSources, missingInventory, staleInventory);

        return new DetectionPrerequisiteTelemetryStatus
        {
            RuleId = rule.RuleId,
            Name = rule.Name,
            Severity = rule.Severity,
            Enabled = rule.Enabled,
            Status = status,
            RequiredSources = requiredSources,
            HealthySources = healthySources.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            MissingSources = missingSources.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            StaleSources = staleSources.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            RecentEventSources = recentEventSources.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            RequiredFields = rule.RequiredFields,
            RequiredEventIds = profile.RequiredEventIds,
            RequiredEventCategories = profile.RequiredEventCategories,
            RequiredEventActions = profile.RequiredEventActions,
            AuditPolicyRequirements = profile.AuditPolicyRequirements,
            InventoryRequirements = profile.InventoryRequirements,
            OptionalSources = profile.OptionalSources,
            Reason = reason
        };
    }

    private static bool SourceAppliesToTargetLevel(string requiredSource, WindowsCoverageLevel targetLevel)
    {
        if (string.Equals(requiredSource, "source-health", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var aliases = WindowsTelemetrySourceCatalog.AliasesFor(requiredSource)
            .Append(requiredSource)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var matchingEntries = WindowsTelemetrySourceCatalog.All
            .Where(entry => aliases.Contains(entry.SourceId) || aliases.Contains(entry.ParserId))
            .ToArray();
        return matchingEntries.Length == 0 || matchingEntries.Any(entry => entry.CoverageLevel <= targetLevel);
    }

    private static string DetermineDetectionStatus(
        DetectionRuleMetadata rule,
        IReadOnlyList<string> requiredSources,
        IReadOnlyList<string> healthySources,
        IReadOnlyList<string> recentEventSources,
        IReadOnlyList<string> missingSources,
        IReadOnlyList<string> staleSources,
        IReadOnlyList<string> missingInventory,
        IReadOnlyList<string> staleInventory)
    {
        if (!rule.Enabled)
        {
            return StatusExcepted;
        }

        if (requiredSources.Count > 0 && healthySources.Count == 0)
        {
            return StatusMissingPrerequisites;
        }

        if (missingInventory.Count > 0)
        {
            return StatusMissingPrerequisites;
        }

        if (staleSources.Count > 0 || staleInventory.Count > 0 || missingSources.Count > 0)
        {
            return recentEventSources.Count > 0 ? StatusPartiallySatisfied : StatusUnknown;
        }

        if (requiredSources.Count > 0 && recentEventSources.Count == 0)
        {
            return StatusUnknown;
        }

        return StatusSatisfied;
    }

    private static string BuildDetectionReason(
        string status,
        IReadOnlyList<string> requiredSources,
        IReadOnlyList<string> healthySources,
        IReadOnlyList<string> recentEventSources,
        IReadOnlyList<string> missingSources,
        IReadOnlyList<string> staleSources,
        IReadOnlyList<string> missingInventory,
        IReadOnlyList<string> staleInventory)
    {
        if (string.Equals(status, StatusSatisfied, StringComparison.OrdinalIgnoreCase))
        {
            return "Required telemetry source health and recent event presence were observed within the lookback.";
        }

        if (missingInventory.Count > 0)
        {
            return $"Missing inventory prerequisite(s): {string.Join(", ", missingInventory)}.";
        }

        if (staleInventory.Count > 0)
        {
            return $"Inventory prerequisite(s) are stale: {string.Join(", ", staleInventory)}.";
        }

        if (requiredSources.Count > 0 && healthySources.Count == 0)
        {
            return $"No required source is healthy. Missing/stale source(s): {string.Join(", ", missingSources.Concat(staleSources).Distinct(StringComparer.OrdinalIgnoreCase))}.";
        }

        if (recentEventSources.Count == 0)
        {
            return "Source health exists, but no recent normalized events for the required source set were observed in the lookback.";
        }

        if (missingSources.Count > 0 || staleSources.Count > 0)
        {
            return $"Some prerequisite sources are missing or stale ({string.Join(", ", missingSources.Concat(staleSources).Distinct(StringComparer.OrdinalIgnoreCase))}); at least one source has recent events.";
        }

        return "Prerequisite state could not be fully determined from current telemetry.";
    }

    private static bool IsGapStatus(string status) => status is SourceHealthStatuses.Missing or SourceHealthStatuses.Disabled or SourceHealthStatuses.Stale or SourceHealthStatuses.Error;

    private static bool IsExcepted(string expectedSourceId, IReadOnlySet<string> exceptedSourceIds) =>
        exceptedSourceIds.Any(excepted => WindowsTelemetrySourceCatalog.SourceMatches(excepted, expectedSourceId)
            || WindowsTelemetrySourceCatalog.SourceMatches(expectedSourceId, excepted));

    private static IReadOnlyDictionary<string, string> MergeDetails(
        IReadOnlyDictionary<string, string> original,
        SourceManifestEntry expected,
        bool reported,
        bool excepted)
    {
        var details = new Dictionary<string, string>(original, StringComparer.OrdinalIgnoreCase)
        {
            ["expected_source"] = "true",
            ["reported_by_agent"] = reported ? "true" : "false",
            ["source_pack"] = expected.SourcePack,
            ["parser_id"] = expected.ParserId
        };

        if (!reported)
        {
            details["coverage_gap"] = "expected_source_not_reported";
        }

        if (excepted)
        {
            details["coverage_exception"] = "active";
        }

        return details;
    }
}
