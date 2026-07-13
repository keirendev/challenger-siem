using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Inventory;
using Challenger.Siem.LinuxAgent.Journal;
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
    .Validate(options => options.HasValidSelfIntegrityBounds(), "Self-integrity bounds are outside the supported range")
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
builder.Services.AddSingleton<LinuxSelfIntegrityStateStore>(services => new LinuxSelfIntegrityStateStore(services.GetRequiredService<IOptions<LinuxAgentOptions>>().Value.SelfIntegrity.StatePath));
builder.Services.AddSingleton<LinuxSelfIntegrityRuntime>();
builder.Services.AddSingleton<ILinuxSelfIntegritySource, LinuxSelfIntegritySource>();
builder.Services.AddSingleton<LinuxSelfIntegrityCollector>();
builder.Services.AddSingleton<LinuxJournalNormalizer>();
builder.Services.AddSingleton<ILinuxJournalSource, LinuxJournalProcessSource>();
builder.Services.AddSingleton<LinuxTransportRuntimeState>();
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
builder.Services.AddSystemd();

var app = builder.Build();
if (args.Contains("--self-integrity-plan", StringComparer.Ordinal))
{
    var collector = app.Services.GetRequiredService<LinuxSelfIntegrityCollector>();
    var plan = await collector.PreflightAsync(CancellationToken.None);
    Console.WriteLine(JsonSerializer.Serialize(plan, JsonDefaults.Options));
    return 0;
}

await app.RunAsync();
return 0;
