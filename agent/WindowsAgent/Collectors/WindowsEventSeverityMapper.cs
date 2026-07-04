namespace Challenger.Siem.WindowsAgent.Collectors;

public static class WindowsEventSeverityMapper
{
    public static string Map(int? level, IEnumerable<string> keywords)
    {
        if (keywords.Any(keyword => keyword.Contains("Audit Success", StringComparison.OrdinalIgnoreCase)))
        {
            return "audit_success";
        }

        if (keywords.Any(keyword => keyword.Contains("Audit Failure", StringComparison.OrdinalIgnoreCase)))
        {
            return "audit_failure";
        }

        return level switch
        {
            1 => "critical",
            2 => "error",
            3 => "warning",
            5 => "verbose",
            _ => "information"
        };
    }
}
