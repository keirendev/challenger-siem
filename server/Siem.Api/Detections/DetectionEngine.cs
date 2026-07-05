using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Detections;

public sealed record DetectionEvaluationResult(
    DetectionRuleMetadata Rule,
    bool PrerequisitesMet,
    bool Matched,
    string Reason);

public sealed class DetectionEngine
{
    public IReadOnlyList<DetectionEvaluationResult> Evaluate(EventEnvelope envelope, IReadOnlySet<string> healthySources)
    {
        return DetectionRuleCatalog.BuiltInRules
            .Where(rule => rule.Enabled)
            .Select(rule => EvaluateRule(rule, envelope, healthySources))
            .ToArray();
    }

    private static DetectionEvaluationResult EvaluateRule(
        DetectionRuleMetadata rule,
        EventEnvelope envelope,
        IReadOnlySet<string> healthySources)
    {
        var prerequisitesMet = rule.RequiredSources.Count == 0
            || rule.RequiredSources.Any(source => healthySources.Contains(source));
        if (!prerequisitesMet)
        {
            return new DetectionEvaluationResult(rule, false, false, "required source missing or stale");
        }

        var categoryMatches = string.Equals(rule.Category, envelope.Normalized?.Category, StringComparison.OrdinalIgnoreCase);
        var actionMatches = rule.RuleId switch
        {
            "tamper.event-log-cleared" => envelope.WindowsEventId == 1102,
            "malware.defender-detection" => envelope.WindowsEventId is 1116 or 1117,
            _ => categoryMatches
        };

        return new DetectionEvaluationResult(
            rule,
            true,
            actionMatches,
            actionMatches ? "event matched rule category or event-id predicate" : "event did not match rule predicate");
    }
}
