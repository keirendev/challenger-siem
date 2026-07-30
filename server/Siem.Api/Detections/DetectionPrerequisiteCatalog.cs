namespace Challenger.Siem.Api.Detections;

public sealed record DetectionPrerequisiteProfile(
    string RuleId,
    IReadOnlyList<int> RequiredEventIds,
    IReadOnlyList<string> RequiredEventCategories,
    IReadOnlyList<string> RequiredEventActions,
    IReadOnlyList<string> AuditPolicyRequirements,
    IReadOnlyList<string> InventoryRequirements,
    IReadOnlyList<string> OptionalSources);

public static class DetectionPrerequisiteCatalog
{
    public static DetectionPrerequisiteProfile ForRule(string ruleId) => new(
        ruleId,
        Array.Empty<int>(),
        Array.Empty<string>(),
        Array.Empty<string>(),
        Array.Empty<string>(),
        Array.Empty<string>(),
        Array.Empty<string>());
}
