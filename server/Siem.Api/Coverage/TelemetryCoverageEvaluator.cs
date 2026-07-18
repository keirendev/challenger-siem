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
        SourceHealthStatuses.Excepted
    };

    public static IReadOnlyList<SourceHealthReport> MergeExpectedSources(
        IReadOnlyList<SourceHealthReport> reportedSources,
        WindowsCoverageLevel targetLevel,
        IReadOnlySet<string> exceptedSourceIds,
        DateTimeOffset now) => MergeExpectedSources(
            reportedSources,
            targetLevel,
            exceptedSourceIds,
            now,
            InferPlatform(reportedSources));

    public static IReadOnlyList<SourceHealthReport> MergeExpectedSources(
        IReadOnlyList<SourceHealthReport> reportedSources,
        WindowsCoverageLevel targetLevel,
        IReadOnlySet<string> exceptedSourceIds,
        DateTimeOffset now,
        string platform)
    {
        var reportedBySource = reportedSources
            .GroupBy(source => source.SourceId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var merged = new List<SourceHealthReport>();

        foreach (var expected in ExpectedFor(platform, targetLevel))
        {
            if (reportedBySource.TryGetValue(expected.SourceId, out var reported))
            {
                var status = SourceHealthRules.EffectiveStatus(reported, now);
                if (expected.Applicability == SourceApplicabilityStatuses.Unsupported)
                {
                    status = SourceHealthStatuses.Unsupported;
                }
                var forceRequiredApplicability = expected.Requirement == SourceRequirementKinds.Mandatory
                    && expected.Applicability == SourceApplicabilityStatuses.Applicable
                    && expected.SourceId != LinuxTelemetrySourceIds.PackageManagement
                    && reported.Applicability != SourceApplicabilityStatuses.Applicable;
                if (forceRequiredApplicability)
                {
                    status = SourceHealthStatuses.Degraded;
                }
                var forceUnsupported = expected.Applicability == SourceApplicabilityStatuses.Unsupported;
                var reportedExcepted = !forceUnsupported && IsExcepted(expected.SourceId, exceptedSourceIds);
                if (reportedExcepted && IsGapStatus(status))
                {
                    status = SourceHealthStatuses.Excepted;
                }

                merged.Add(reported with
                {
                    Platform = reported.Platform ?? expected.Platform,
                    SourceKind = reported.SourceKind ?? expected.SourceKind,
                    SourceNamespace = reported.SourceNamespace ?? expected.SourceNamespace,
                    CoverageLevel = expected.CoverageLevel,
                    Applicability = forceUnsupported || forceRequiredApplicability
                        ? expected.Applicability
                        : reported.Applicability ?? expected.Applicability,
                    ApplicabilityReason = forceUnsupported || forceRequiredApplicability
                        ? expected.ApplicabilityReason
                        : reported.ApplicabilityReason ?? expected.ApplicabilityReason,
                    Status = status,
                    Required = expected.Required,
                    Requirement = expected.Requirement ?? reported.Requirement,
                    ApplicableRoles = expected.ApplicableRoles ?? reported.ApplicableRoles,
                    Enabled = forceUnsupported ? false : reported.Enabled,
                    PrerequisiteStatuses = forceUnsupported
                        ? expected.Prerequisites.ToDictionary(item => item, _ => SourceEvidenceStatuses.Unsupported, StringComparer.Ordinal)
                        : forceRequiredApplicability
                            ? expected.Prerequisites.ToDictionary(item => item, _ => SourceEvidenceStatuses.Degraded, StringComparer.Ordinal)
                            : reported.PrerequisiteStatuses,
                    EventFamilyStatuses = forceUnsupported
                        ? expected.EventFamilies.ToDictionary(item => item, _ => SourceEvidenceStatuses.Unsupported, StringComparer.Ordinal)
                        : forceRequiredApplicability
                            ? expected.EventFamilies.ToDictionary(item => item, _ => SourceEvidenceStatuses.Unknown, StringComparer.Ordinal)
                            : reported.EventFamilyStatuses,
                    Details = MergeDetails(reported.Details, expected, reported: true, reportedExcepted)
                });
                continue;
            }

            var missingExcepted = expected.Applicability != SourceApplicabilityStatuses.Unsupported
                && IsExcepted(expected.SourceId, exceptedSourceIds);
            var missingStatus = MissingStatus(expected, missingExcepted);
            merged.Add(new SourceHealthReport
            {
                SourceId = expected.SourceId,
                Platform = expected.Platform,
                SourceKind = expected.SourceKind,
                DisplayName = expected.DisplayName,
                Channel = expected.Channel,
                SourceNamespace = expected.SourceNamespace,
                Facility = expected.Facility,
                Unit = expected.Unit,
                Applicability = expected.Applicability,
                ApplicabilityReason = expected.ApplicabilityReason,
                CoverageLevel = expected.CoverageLevel,
                Status = missingStatus,
                Required = expected.Required,
                Requirement = expected.Requirement,
                ApplicableRoles = expected.ApplicableRoles,
                Enabled = expected.EnabledByDefault,
                ErrorCode = missingExcepted || missingStatus is SourceHealthStatuses.NotApplicable or SourceHealthStatuses.Unsupported
                    ? null
                    : "expected_source_not_reported",
                ErrorMessage = missingExcepted || missingStatus is SourceHealthStatuses.NotApplicable or SourceHealthStatuses.Unsupported
                    ? null
                    : "Expected source has not been reported by agent source-health heartbeat.",
                PrerequisiteStatuses = expected.Prerequisites.ToDictionary(
                    prerequisite => prerequisite,
                    _ => EvidenceStatusForMissing(missingStatus),
                    StringComparer.Ordinal),
                EventFamilyStatuses = expected.EventFamilies.ToDictionary(
                    family => family,
                    _ => EvidenceStatusForMissing(missingStatus),
                    StringComparer.Ordinal),
                Details = MergeDetails(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), expected, reported: false, missingExcepted)
            });
        }

        var linuxPlatform = string.Equals(platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase);
        foreach (var custom in reportedSources.Where(source => (!linuxPlatform || source.CoverageLevel <= targetLevel)
            && !merged.Any(item => string.Equals(item.SourceId, source.SourceId, StringComparison.OrdinalIgnoreCase))))
        {
            merged.Add(custom with { Status = SourceHealthRules.EffectiveStatus(custom, now) });
        }

        return merged
            .OrderBy(source => source.CoverageLevel)
            .ThenByDescending(IsMandatoryForCoverage)
            .ThenBy(source => source.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static CoverageSummary RecalculateSummary(
        CoverageSummary summary,
        IReadOnlyList<SourceHealthReport> sources,
        WindowsCoverageLevel targetLevel)
    {
        var platform = summary.Platform ?? InferPlatform(sources);
        var inScopeSources = string.Equals(platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase)
            ? sources.Where(source => source.CoverageLevel <= targetLevel).ToArray()
            : sources.ToArray();
        var missingMandatory = inScopeSources.Count(source => IsMandatoryForCoverage(source)
            && (string.Equals(source.Status, SourceHealthStatuses.Missing, StringComparison.OrdinalIgnoreCase)
                || string.Equals(source.Status, SourceHealthStatuses.Disabled, StringComparison.OrdinalIgnoreCase)));
        var stale = CountStatus(inScopeSources, SourceHealthStatuses.Stale);
        var error = CountStatus(inScopeSources, SourceHealthStatuses.Error);
        var degraded = CountStatus(inScopeSources, SourceHealthStatuses.Degraded);
        var permissionDenied = CountStatus(inScopeSources, SourceHealthStatuses.PermissionDenied);
        var unsupported = CountStatus(inScopeSources, SourceHealthStatuses.Unsupported);
        var excepted = CountStatus(inScopeSources, SourceHealthStatuses.Excepted);
        var notApplicable = CountStatus(inScopeSources, SourceHealthStatuses.NotApplicable);
        var currentLevel = CalculateCurrentLevel(inScopeSources, targetLevel, platform);
        var overallStatus = CalculateOverallStatus(inScopeSources);

        return summary with
        {
            Platform = platform,
            TargetLevel = targetLevel,
            CurrentLevel = currentLevel,
            OverallStatus = overallStatus,
            MissingMandatorySources = missingMandatory,
            StaleSources = stale,
            ErrorSources = error,
            DegradedSources = degraded,
            PermissionDeniedSources = permissionDenied,
            UnsupportedSources = unsupported,
            ExceptedSources = excepted,
            NotApplicableSources = notApplicable
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
            Platform = InferPlatform(sources),
            TargetLevel = targetLevel,
            QueueDepth = queueDepth,
            LastHeartbeatTime = lastHeartbeatTime
        }, sources, targetLevel);
    }

    public static WindowsCoverageLevel CalculateCurrentLevel(
        IReadOnlyList<SourceHealthReport> sources,
        WindowsCoverageLevel targetLevel) => CalculateCurrentLevel(sources, targetLevel, InferPlatform(sources));

    public static WindowsCoverageLevel CalculateCurrentLevel(
        IReadOnlyList<SourceHealthReport> sources,
        WindowsCoverageLevel targetLevel,
        string platform)
    {
        var current = WindowsCoverageLevel.L0;
        foreach (var level in new[] { WindowsCoverageLevel.L1, WindowsCoverageLevel.L2, WindowsCoverageLevel.L3, WindowsCoverageLevel.L4 })
        {
            if (level > targetLevel)
            {
                break;
            }

            var expected = ExpectedFor(platform, level)
                .Where(expected => expected.CoverageLevel <= level)
                .ToArray();

            if (level == WindowsCoverageLevel.L4
                && string.Equals(platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase))
            {
                if (!IsStrictLinuxL4Satisfied(expected, sources))
                {
                    break;
                }

                current = level;
                continue;
            }

            var required = expected
                .Where(expected => expected.Requirement == SourceRequirementKinds.Mandatory
                    || (expected.Requirement == SourceRequirementKinds.RoleSpecific
                        && sources.Any(source => string.Equals(source.SourceId, expected.SourceId, StringComparison.OrdinalIgnoreCase)
                            && source.Applicability == SourceApplicabilityStatuses.Applicable))
                    || (expected.Requirement is null && expected.Required))
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

            if (string.Equals(platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase))
            {
                var levelSpecific = expected.Where(item => item.CoverageLevel == level).ToArray();
                var hasLevelSpecificEvidence = levelSpecific.Any(item => sources.Any(source =>
                    string.Equals(source.SourceId, item.SourceId, StringComparison.OrdinalIgnoreCase)
                    && source.Enabled
                    && source.Applicability is not SourceApplicabilityStatuses.NotApplicable and not SourceApplicabilityStatuses.Unsupported
                    && CoveredSourceStatuses.Contains(source.Status)));
                if (!hasLevelSpecificEvidence)
                {
                    break;
                }
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

        if (HasStatus(sources, SourceHealthStatuses.Error))
        {
            return SourceHealthStatuses.Error;
        }
        if (sources.Any(source => IsMandatoryForCoverage(source)
            && string.Equals(source.Status, SourceHealthStatuses.PermissionDenied, StringComparison.OrdinalIgnoreCase)))
        {
            return SourceHealthStatuses.PermissionDenied;
        }
        if (sources.Any(source => IsMandatoryForCoverage(source)
            && string.Equals(source.Status, SourceHealthStatuses.Unsupported, StringComparison.OrdinalIgnoreCase)))
        {
            return SourceHealthStatuses.Unsupported;
        }
        if (sources.Any(source => IsMandatoryForCoverage(source)
            && (string.Equals(source.Status, SourceHealthStatuses.Missing, StringComparison.OrdinalIgnoreCase)
                || string.Equals(source.Status, SourceHealthStatuses.Disabled, StringComparison.OrdinalIgnoreCase))))
        {
            return SourceHealthStatuses.Missing;
        }
        if (HasStatus(sources, SourceHealthStatuses.Stale))
        {
            return SourceHealthStatuses.Stale;
        }
        if (HasStatus(sources, SourceHealthStatuses.PermissionDenied))
        {
            return SourceHealthStatuses.PermissionDenied;
        }
        if (HasStatus(sources, SourceHealthStatuses.Degraded) || HasStatus(sources, SourceHealthStatuses.Unsupported))
        {
            return SourceHealthStatuses.Degraded;
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
                Reason = $"Rule requires source coverage above target level {targetLevel}; it is not counted as a prerequisite gap at this target."
            };
        }

        var healthySources = new List<string>();
        var staleSources = new List<string>();
        var missingSources = new List<string>();
        var recentEventSources = new List<string>();
        var satisfiedSources = new List<string>();

        foreach (var requiredSource in inScopeRequiredSources)
        {
            if (string.Equals(requiredSource, "source-health", StringComparison.OrdinalIgnoreCase))
            {
                if (sources.Any(source => source.Reported))
                {
                    healthySources.Add(requiredSource);
                    recentEventSources.Add(requiredSource);
                    satisfiedSources.Add(requiredSource);
                }
                else
                {
                    missingSources.Add(requiredSource);
                }

                continue;
            }

            var matching = sources
                .Where(source => SourceMatches(requiredSource, source))
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

            if (matching.Any(IsCoveredSource))
            {
                healthySources.Add(requiredSource);
            }
            else if (!staleSources.Contains(requiredSource, StringComparer.OrdinalIgnoreCase))
            {
                missingSources.Add(requiredSource);
            }

            if (matching.Any(HasCurrentSourceObservation))
            {
                recentEventSources.Add(requiredSource);
            }

            if (matching.Any(source => IsCoveredSource(source) && HasCurrentSourceObservation(source)))
            {
                satisfiedSources.Add(requiredSource);
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

        var status = DetermineDetectionStatus(rule, inScopeRequiredSources, healthySources, recentEventSources, satisfiedSources, missingInventory, staleInventory);
        var reason = BuildDetectionReason(status, inScopeRequiredSources, healthySources, recentEventSources, satisfiedSources, missingSources, staleSources, missingInventory, staleInventory);
        var hasHealthyAlternative = inScopeRequiredSources.Length > 0 && healthySources.Count > 0;

        return new DetectionPrerequisiteTelemetryStatus
        {
            RuleId = rule.RuleId,
            Name = rule.Name,
            Severity = rule.Severity,
            Enabled = rule.Enabled,
            Status = status,
            RequiredSources = requiredSources,
            HealthySources = healthySources.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            MissingSources = hasHealthyAlternative
                ? Array.Empty<string>()
                : missingSources.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            StaleSources = hasHealthyAlternative
                ? Array.Empty<string>()
                : staleSources.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
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
            .Concat(LinuxTelemetrySourceCatalog.All)
            .Where(entry => aliases.Any(alias => SourceNameEquals(alias, entry.SourceId)
                || SourceNameEquals(alias, entry.ParserId)
                || SourceNameEquals(alias, entry.SourceKind)))
            .ToArray();
        return matchingEntries.Length == 0 || matchingEntries.Any(entry => entry.CoverageLevel <= targetLevel);
    }

    private static string DetermineDetectionStatus(
        DetectionRuleMetadata rule,
        IReadOnlyList<string> requiredSources,
        IReadOnlyList<string> healthySources,
        IReadOnlyList<string> recentEventSources,
        IReadOnlyList<string> satisfiedSources,
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

        if (requiredSources.Count > 0 && satisfiedSources.Count == 0)
        {
            return recentEventSources.Count > 0 ? StatusPartiallySatisfied : StatusUnknown;
        }

        if (staleInventory.Count > 0)
        {
            return recentEventSources.Count > 0 ? StatusPartiallySatisfied : StatusUnknown;
        }

        return StatusSatisfied;
    }

    private static string BuildDetectionReason(
        string status,
        IReadOnlyList<string> requiredSources,
        IReadOnlyList<string> healthySources,
        IReadOnlyList<string> recentEventSources,
        IReadOnlyList<string> satisfiedSources,
        IReadOnlyList<string> missingSources,
        IReadOnlyList<string> staleSources,
        IReadOnlyList<string> missingInventory,
        IReadOnlyList<string> staleInventory)
    {
        if (string.Equals(status, StatusSatisfied, StringComparison.OrdinalIgnoreCase))
        {
            return requiredSources.Count == 0
                ? "No source prerequisite is required and current inventory prerequisites are satisfied."
                : "At least one required telemetry source alternative is healthy and has a current event or successful polling observation.";
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

        if (requiredSources.Count > 0 && satisfiedSources.Count == 0 && recentEventSources.Count == 0)
        {
            return "Source health exists, but no current normalized event or successful passive polling observation was found for a healthy required source alternative.";
        }

        if (requiredSources.Count > 0 && satisfiedSources.Count == 0 && recentEventSources.Count > 0)
        {
            return "Current observations exist, but no single required source alternative is both healthy and current.";
        }

        return "Prerequisite state could not be fully determined from current telemetry.";
    }

    private static IReadOnlyList<SourceManifestEntry> ExpectedFor(string platform, WindowsCoverageLevel targetLevel) =>
        string.Equals(platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase)
            ? LinuxTelemetrySourceCatalog.ExpectedFor(targetLevel)
            : WindowsTelemetrySourceCatalog.ExpectedFor(targetLevel);

    private static string InferPlatform(IReadOnlyList<SourceHealthReport> sources) =>
        sources.Any(source => string.Equals(source.Platform, TelemetryPlatforms.Linux, StringComparison.Ordinal))
            ? TelemetryPlatforms.Linux
            : TelemetryPlatforms.Windows;

    private static string MissingStatus(SourceManifestEntry expected, bool excepted)
    {
        if (expected.Applicability == SourceApplicabilityStatuses.Unsupported) return SourceHealthStatuses.Unsupported;
        if (excepted) return SourceHealthStatuses.Excepted;
        if (expected.Applicability == SourceApplicabilityStatuses.NotApplicable) return SourceHealthStatuses.NotApplicable;
        if (expected.Applicability == SourceApplicabilityStatuses.Unknown) return SourceHealthStatuses.Degraded;
        return SourceHealthStatuses.Missing;
    }

    private static string EvidenceStatusForMissing(string sourceStatus) => sourceStatus switch
    {
        SourceHealthStatuses.Excepted => SourceEvidenceStatuses.Excepted,
        SourceHealthStatuses.Unsupported => SourceEvidenceStatuses.Unsupported,
        SourceHealthStatuses.NotApplicable => SourceEvidenceStatuses.NotApplicable,
        SourceHealthStatuses.Degraded => SourceEvidenceStatuses.Unknown,
        _ => SourceEvidenceStatuses.Missing
    };

    private static bool IsMandatoryForCoverage(SourceHealthReport source) => source.Requirement switch
    {
        SourceRequirementKinds.Mandatory => true,
        SourceRequirementKinds.RoleSpecific => source.Applicability == SourceApplicabilityStatuses.Applicable,
        SourceRequirementKinds.Optional => false,
        _ => source.Required
    };

    private static int CountStatus(IReadOnlyList<SourceHealthReport> sources, string status) =>
        sources.Count(source => string.Equals(source.Status, status, StringComparison.OrdinalIgnoreCase));

    private static bool HasStatus(IReadOnlyList<SourceHealthReport> sources, string status) =>
        sources.Any(source => string.Equals(source.Status, status, StringComparison.OrdinalIgnoreCase));

    private static bool IsGapStatus(string status) => status is
        SourceHealthStatuses.Missing or
        SourceHealthStatuses.Disabled or
        SourceHealthStatuses.Stale or
        SourceHealthStatuses.Degraded or
        SourceHealthStatuses.PermissionDenied or
        SourceHealthStatuses.Unsupported or
        SourceHealthStatuses.Error;

    private static bool SourceMatches(string expectedOrAlias, string sourceId) =>
        SourceNameEquals(expectedOrAlias, sourceId)
        || WindowsTelemetrySourceCatalog.SourceMatches(expectedOrAlias, sourceId)
        || LinuxTelemetrySourceCatalog.All.Any(entry =>
            (SourceNameEquals(entry.SourceId, expectedOrAlias)
                || SourceNameEquals(entry.ParserId, expectedOrAlias))
            && SourceNameEquals(entry.SourceId, sourceId));

    private static bool SourceMatches(string expectedOrAlias, SourceTelemetryCoverage source) =>
        SourceMatches(expectedOrAlias, source.SourceId)
        || SourceNameEquals(expectedOrAlias, source.SourceKind)
        || WindowsTelemetrySourceCatalog.All
            .Concat(LinuxTelemetrySourceCatalog.All)
            .Any(entry => SourceNameEquals(entry.SourceId, source.SourceId)
                && SourceNameEquals(expectedOrAlias, entry.SourceKind));

    private static bool IsCoveredSource(SourceTelemetryCoverage source) =>
        CoveredSourceStatuses.Contains(source.Status);

    private static bool HasCurrentSourceObservation(SourceTelemetryCoverage source) =>
        source.RecentEventCount > 0
        || (SourceHealthRules.IsSuccessfulPollingSource(source.SourceId)
            && source.ObservedAt.HasValue
            && string.Equals(source.Status, SourceHealthStatuses.Healthy, StringComparison.OrdinalIgnoreCase));

    private static bool IsStrictLinuxL4Satisfied(
        IReadOnlyList<SourceManifestEntry> expected,
        IReadOnlyList<SourceHealthReport> sources)
    {
        var sourceById = sources
            .GroupBy(source => source.SourceId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

        bool IsExactlyHealthy(SourceManifestEntry entry)
        {
            if (!sourceById.TryGetValue(entry.SourceId, out var source))
            {
                return false;
            }

            return source.Enabled
                && source.Applicability == SourceApplicabilityStatuses.Applicable
                && string.Equals(source.Status, SourceHealthStatuses.Healthy, StringComparison.OrdinalIgnoreCase);
        }

        var lowerMandatory = expected
            .Where(entry => entry.CoverageLevel < WindowsCoverageLevel.L4)
            .Where(entry => entry.Requirement == SourceRequirementKinds.Mandatory
                || (entry.Requirement == SourceRequirementKinds.RoleSpecific
                    && sourceById.TryGetValue(entry.SourceId, out var source)
                    && source.Applicability == SourceApplicabilityStatuses.Applicable)
                || (entry.Requirement is null && entry.Required))
            .ToArray();
        if (lowerMandatory.Length == 0 || lowerMandatory.Any(entry => !IsExactlyHealthy(entry)))
        {
            return false;
        }

        var l4Mandatory = expected
            .Where(entry => entry.CoverageLevel == WindowsCoverageLevel.L4
                && entry.Requirement == SourceRequirementKinds.Mandatory)
            .ToArray();
        var canonicalL4Mandatory = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            LinuxTelemetrySourceIds.PolicyPostureDrift,
            LinuxTelemetrySourceIds.AgentPerformanceSlo
        };
        if (!canonicalL4Mandatory.SetEquals(l4Mandatory.Select(entry => entry.SourceId))
            || l4Mandatory.Any(entry => !IsExactlyHealthy(entry)))
        {
            return false;
        }

        var l4RoleSources = expected
            .Where(entry => entry.CoverageLevel == WindowsCoverageLevel.L4
                && entry.Requirement == SourceRequirementKinds.RoleSpecific)
            .ToArray();
        if (l4RoleSources.Length == 0)
        {
            return false;
        }

        foreach (var roleSource in l4RoleSources)
        {
            if (!sourceById.TryGetValue(roleSource.SourceId, out var source)
                || source.Applicability is not SourceApplicabilityStatuses.Applicable and not SourceApplicabilityStatuses.NotApplicable)
            {
                return false;
            }

            if (source.Applicability == SourceApplicabilityStatuses.Applicable
                && (!source.Enabled || !string.Equals(source.Status, SourceHealthStatuses.Healthy, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        return true;
    }

    private static bool SourceNameEquals(string? left, string? right) =>
        string.Equals(NormalizeSourceName(left), NormalizeSourceName(right), StringComparison.Ordinal);

    private static string NormalizeSourceName(string? value) =>
        (value ?? string.Empty).Replace('_', '-').ToLowerInvariant();

    private static bool IsExcepted(string expectedSourceId, IReadOnlySet<string> exceptedSourceIds) =>
        exceptedSourceIds.Any(excepted => SourceMatches(excepted, expectedSourceId)
            || SourceMatches(expectedSourceId, excepted));

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
