namespace Challenger.Siem.Api.SocAgent;

public sealed class SocAgentCodexAppServerOptions
{
    public const string SectionName = "SocAgent:CodexAppServer";

    public bool Enabled { get; set; } = true;
    public string? ExecutablePath { get; set; }
    public string StateDirectory { get; set; } = ".local/soc-agent/codex";
    public string WorkingDirectory { get; set; } = ".local/soc-agent/codex/work";
    public int StartupTimeoutSeconds { get; set; } = 20;
    public int RequestTimeoutSeconds { get; set; } = 30;
    public int LoginTimeoutSeconds { get; set; } = 900;
    public int MaxJsonLineBytes { get; set; } = 1024 * 1024;
}

public sealed record SocAgentCodexAccountStatus(
    bool IsAvailable,
    bool IsConnected,
    string State,
    string? PlanType,
    string OperatorMessage);

public sealed record SocAgentCodexLoginStatus(
    bool IsAvailable,
    bool IsActive,
    string State,
    string? VerificationUrl,
    string? UserCode,
    string OperatorMessage);

public sealed record SocAgentCodexLoginStartResult(
    bool Started,
    SocAgentCodexLoginStatus Status);

public sealed record SocAgentCodexLoginCancelResult(
    bool Cancelled,
    SocAgentCodexLoginStatus Status);

public interface ISocAgentCodexAppServerClient
{
    SocAgentCodexAccountStatus GetAccountStatus();

    SocAgentCodexLoginStatus GetLoginStatus();

    Task<SocAgentCodexLoginStartResult> StartDeviceLoginAsync(CancellationToken cancellationToken);

    Task<SocAgentCodexLoginCancelResult> CancelDeviceLoginAsync(CancellationToken cancellationToken);
}

internal sealed record SocAgentCodexCredential(
    string AccessToken,
    string? AccountId);

internal interface ISocAgentCodexCredentialBroker
{
    Task<SocAgentCodexCredential> GetCredentialAsync(CancellationToken cancellationToken);
}
