using Challenger.Siem.Contracts.V2;

namespace Challenger.Siem.Api.Auth;

public static class ServiceRoles
{
    public const string Service = "service";
}

public enum ServicePermission
{
    ReviewMetadata,
    ReviewSensitive,
    ManageInvestigations,
    ManageDetections,
    ManageAgents,
    ExportEvents,
    ReviewAudit
}

public static class ServiceAuthorization
{
    public static bool HasPermission(string? role, ServicePermission permission) =>
        string.Equals(role, ServiceRoles.Service, StringComparison.Ordinal);

    public static string Role(System.Security.Claims.ClaimsPrincipal principal) => ServiceRoles.Service;
}

public static class ServiceAlertPolicy
{
    public static AlertRecord Apply(AlertRecord source, string role) => source;
}

public static class ServiceEventPolicy
{
    public static EventEnvelope Apply(EventEnvelope source, string role) => source;
}
