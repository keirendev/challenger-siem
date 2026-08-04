using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Inventory;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.KernelNetwork;
using Challenger.Siem.LinuxAgent.L4;
using Challenger.Siem.LinuxAgent.Passive;
using Challenger.Siem.LinuxAgent.SelfIntegrity;
using Challenger.Siem.LinuxAgent.Services;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Options;

if (!OperatingSystem.IsLinux())
{
    Console.Error.WriteLine("Challenger SIEM Linux Agent requires Linux.");
    return 2;
}

var builder = Host.CreateApplicationBuilder(args);
// The agent reads the system journal. Per-request HttpClient information logs would therefore
// be recollected as new events and create a feedback loop after every successful drain.
// Keep transport failures visible while suppressing routine request/response chatter.
builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);
var path = Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG") ?? "/etc/challenger-siem-agent/agentsettings.json";
builder.Configuration.AddJsonFile(path, optional: false, reloadOnChange: true).AddEnvironmentVariables("CHALLENGER_SIEM_AGENT_");
builder.Services.AddOptions<LinuxAgentOptions>().Bind(builder.Configuration.GetSection(LinuxAgentOptions.SectionName))
    .Validate(options => !string.IsNullOrWhiteSpace(options.AgentId), "AgentId is required")
    .Validate(options => options.ServerBaseUrl is not null && options.ServerBaseUrl.Scheme == Uri.UriSchemeHttps, "ServerBaseUrl must use HTTPS")
    .Validate(options => !string.IsNullOrWhiteSpace(options.ApiToken) || !string.IsNullOrWhiteSpace(options.EnrollmentToken), "A credential is required")
    .Validate(options => options.HeartbeatIntervalSeconds > 0 && options.DrainBatchSize is > 0 and <= 500,
        "Heartbeat interval or drain batch size is outside the supported range")
    .Validate(options => options.HasValidInventoryBounds(), "Inventory bounds are outside the supported range")
    .Validate(options => options.HasValidJournalBounds(), "Journal bounds are outside the supported range")
    .Validate(options => options.HasValidAuditBounds(), "Audit router bounds are outside the supported range")
    .Validate(options => options.HasValidQueueBounds(), "Queue bounds are outside the supported range")
    .Validate(options => options.HasValidSelfIntegrityBounds(), "Self-integrity bounds are outside the supported range")
    .Validate(options => options.HasValidPassiveTelemetryBounds(), "Passive telemetry bounds are outside the supported range")
    .Validate(options => options.HasValidKernelNetworkTelemetryBounds(), "Kernel network telemetry bounds are outside the supported range")
    .Validate(options => options.HasValidL4TelemetryBounds(), "L4 telemetry bounds are outside the supported range")
    .ValidateOnStart();

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IAgentTransportConfiguration>(services => services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value);
builder.Services.AddSingleton(services => new LinuxStateStore(services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.State.Path));
builder.Services.AddSingleton<IEventQueue>(services =>
{
    var queue = services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.Queue;
    return new SqliteEventQueue(new AgentQueueOptions
    {
        Path = queue.Path,
        MaxSizeMb = queue.MaxSizeMb,
        MaxSendAttempts = queue.MaxSendAttempts,
        MaxBackoffSeconds = queue.MaxBackoffSeconds,
        WarningSizePercent = queue.WarningSizePercent
    }, services.GetRequiredService<ILogger<SqliteEventQueue>>());
});
builder.Services.AddHttpClient<SiemIngestClient>((services, client) =>
{
    client.BaseAddress = services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.ServerBaseUrl;
    client.Timeout = TimeSpan.FromSeconds(30);
});
builder.Services.AddSingleton<LinuxEnrollmentService>();
builder.Services.AddSingleton<LinuxJournalRuntime>();
builder.Services.AddSingleton<ILinuxAcknowledgementObserver>(services => services.GetRequiredService<LinuxJournalRuntime>());
builder.Services.AddSingleton<ILinuxInventoryObserver>(services => services.GetRequiredService<LinuxJournalRuntime>());
builder.Services.AddSingleton<LinuxSelfIntegrityStateStore>(services => new LinuxSelfIntegrityStateStore(services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.SelfIntegrity.StatePath));
builder.Services.AddSingleton<LinuxSelfIntegrityRuntime>();
builder.Services.AddSingleton<ILinuxAcknowledgementObserver>(services => services.GetRequiredService<LinuxSelfIntegrityRuntime>());
builder.Services.AddSingleton<ILinuxSelfIntegritySource, LinuxSelfIntegritySource>();
builder.Services.AddSingleton<LinuxSelfIntegrityCollector>();
builder.Services.AddSingleton<LinuxJournalNormalizer>();
builder.Services.AddSingleton<LinuxAuditRouterRuntime>();
builder.Services.AddSingleton<LinuxAuditRouter>();
builder.Services.AddSingleton<ILinuxAcknowledgementObserver>(services => services.GetRequiredService<LinuxAuditRouter>());
builder.Services.AddSingleton<ILinuxJournalSource, LinuxJournalProcessSource>();
builder.Services.AddSingleton<LinuxTransportRuntimeState>();
builder.Services.AddSingleton<LinuxPassiveTelemetryStateStore>(services =>
    new LinuxPassiveTelemetryStateStore(
        services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.PassiveTelemetry.StatePath,
        "/var/lib/challenger-siem-agent"));
builder.Services.AddSingleton<LinuxSocketOwnershipCache>();
builder.Services.AddSingleton<ILinuxProcessSnapshotSource, LinuxProcfsProcessSource>();
builder.Services.AddSingleton<ILinuxNetworkSnapshotSource, LinuxProcfsNetworkSource>();
builder.Services.AddSingleton<ILinuxHostMetricsSource, LinuxHostMetricsSource>();
builder.Services.AddSingleton<LinuxPassiveTelemetryCollector>();
builder.Services.AddSingleton<LinuxPassiveTelemetryRuntime>();
builder.Services.AddSingleton<ILinuxAcknowledgementObserver>(services => services.GetRequiredService<LinuxPassiveTelemetryRuntime>());
builder.Services.AddSingleton<LinuxKernelNetworkStateStore>(services =>
    new LinuxKernelNetworkStateStore(services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.KernelNetworkTelemetry.StatePath));
builder.Services.AddSingleton<LinuxKernelNetworkRuntime>();
builder.Services.AddSingleton<ILinuxAcknowledgementObserver>(services => services.GetRequiredService<LinuxKernelNetworkRuntime>());
builder.Services.AddSingleton<LinuxL4TelemetryStateStore>(services =>
    new LinuxL4TelemetryStateStore(
        services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.L4Telemetry.StatePath,
        "/var/lib/challenger-siem-agent"));
builder.Services.AddSingleton<ILinuxAgentSloSource, LinuxAgentSloSource>();
builder.Services.AddSingleton<LinuxL4TelemetryCollector>();
builder.Services.AddSingleton<LinuxL4TelemetryRuntime>();
builder.Services.AddSingleton<ILinuxAcknowledgementObserver>(services => services.GetRequiredService<LinuxL4TelemetryRuntime>());
builder.Services.AddSingleton<ILinuxInventoryObserver>(services => services.GetRequiredService<LinuxL4TelemetryRuntime>());
builder.Services.AddSingleton<LinuxQueueDrainer>();
builder.Services.AddSingleton<ILinuxInventorySource, LinuxInventorySource>();
builder.Services.AddSingleton<ILinuxInventoryCollector>(services =>
{
    var options = services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.Inventory;
    return new LinuxInventory(
        services.GetRequiredService<ILinuxInventorySource>(),
        services.GetRequiredService<TimeProvider>(),
        TimeSpan.FromSeconds(options.CollectionTimeoutSeconds),
        options.MaxSerializedBytes);
});
builder.Services.AddHostedService<LinuxAgentWorker>();
builder.Services.AddHostedService<LinuxJournalService>();
builder.Services.AddHostedService<LinuxInventoryService>();
builder.Services.AddHostedService<LinuxSelfIntegrityService>();
builder.Services.AddHostedService<LinuxPassiveTelemetryService>();
builder.Services.AddHostedService<LinuxKernelNetworkService>();
builder.Services.AddHostedService<LinuxL4TelemetryService>();
builder.Services.AddSystemd();

var app = builder.Build();
if (args.Contains("--self-integrity-plan", StringComparer.Ordinal))
{
    var collector = app.Services.GetRequiredService<LinuxSelfIntegrityCollector>();
    var plan = await collector.PreflightAsync(CancellationToken.None);
    Console.WriteLine(JsonSerializer.Serialize(plan, JsonDefaults.Options));
    return 0;
}
if (args.Contains("--passive-telemetry-plan", StringComparer.Ordinal))
{
    var collector = app.Services.GetRequiredService<LinuxPassiveTelemetryCollector>();
    Console.WriteLine(JsonSerializer.Serialize(collector.Preflight(), JsonDefaults.Options));
    return 0;
}
if (args.Contains("--audit-plan", StringComparer.Ordinal))
{
    var router = app.Services.GetRequiredService<LinuxAuditRouter>();
    Console.WriteLine(JsonSerializer.Serialize(router.Preflight(), JsonDefaults.Options));
    return 0;
}
if (args.Contains("--lifecycle-plan", StringComparer.Ordinal))
{
    var audit = app.Services.GetRequiredService<LinuxAuditRouter>();
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        audit = audit.Preflight(),
        host_changes = "none",
        service_scope = "challenger-siem-agent-only",
        rollback = "Disable logical sources and preserve queue, checkpoints, credentials, TLS, private state, and host producer configuration."
    }, JsonDefaults.Options));
    return 0;
}
if (args.Contains("--l4-telemetry-plan", StringComparer.Ordinal))
{
    var options = app.Services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value;
    var inventory = app.Services.GetRequiredService<ILinuxInventoryCollector>();
    var snapshots = await inventory.CollectAsync(options.AgentId, Environment.MachineName, CancellationToken.None);
    var collector = app.Services.GetRequiredService<LinuxL4TelemetryCollector>();
    Console.WriteLine(JsonSerializer.Serialize(collector.Preflight(snapshots), JsonDefaults.Options));
    return 0;
}
if (args.Contains("--kernel-network-plan", StringComparer.Ordinal))
{
    var options = app.Services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value;
    Console.WriteLine(JsonSerializer.Serialize(LinuxKernelNetworkPlanBuilder.Build(options), JsonDefaults.Options));
    return 0;
}

await app.RunAsync();
return 0;
