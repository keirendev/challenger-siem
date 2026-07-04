using Challenger.Siem.WindowsAgent.Collectors;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Queue;
using Challenger.Siem.WindowsAgent.Services;
using Challenger.Siem.WindowsAgent.State;
using Challenger.Siem.WindowsAgent.Transport;
using Microsoft.Extensions.Options;

var builder = Host.CreateApplicationBuilder(args);

var defaultConfigPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "ChallengerSIEM",
    "Agent",
    "agentsettings.json");
var executableDirectoryConfigPath = Path.Combine(AppContext.BaseDirectory, "agentsettings.json");
var configPath = Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG") ?? defaultConfigPath;

builder.Configuration
    .AddJsonFile(executableDirectoryConfigPath, optional: true, reloadOnChange: true)
    .AddJsonFile(configPath, optional: true, reloadOnChange: true)
    .AddEnvironmentVariables(prefix: "CHALLENGER_SIEM_AGENT_");

builder.Services
    .AddOptions<AgentOptions>()
    .Configure<IConfiguration>((options, configuration) =>
    {
        var section = configuration.GetSection(AgentOptions.SectionName);
        if (section.Exists())
        {
            section.Bind(options);
        }

        // Also support agentsettings.json files that place AgentOptions fields at the root.
        configuration.Bind(options);
    })
    .Validate(options => !string.IsNullOrWhiteSpace(options.AgentId), "Agent:AgentId is required.")
    .Validate(options => options.ServerBaseUrl is not null, "Agent:ServerBaseUrl is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.ApiToken), "Agent:ApiToken is required.")
    .Validate(options => options.Channels.Count > 0, "At least one required channel is required.")
    .Validate(options => options.Batching.MaxEvents is > 0 and <= 500, "Batching:MaxEvents must be between 1 and 500.")
    .Validate(options => options.PollIntervalSeconds > 0, "PollIntervalSeconds must be greater than zero.")
    .Validate(options => options.HeartbeatIntervalSeconds > 0, "HeartbeatIntervalSeconds must be greater than zero.")
    .ValidateOnStart();

builder.Services.AddSingleton<IWindowsEventCollector, WindowsEventCollector>();
builder.Services.AddSingleton<IChannelStateStore, JsonChannelStateStore>();
builder.Services.AddSingleton<IEventQueue, SqliteEventQueue>();
builder.Services.AddSingleton<AgentRuntimeState>();
builder.Services.AddHttpClient<SiemIngestClient>((serviceProvider, client) =>
{
    var options = serviceProvider.GetRequiredService<IOptions<AgentOptions>>().Value;
    client.BaseAddress = options.ServerBaseUrl;
    client.Timeout = TimeSpan.FromSeconds(30);
});
builder.Services.AddHostedService<AgentWorker>();

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Challenger SIEM Agent";
});

var host = builder.Build();
try
{
    host.Run();
}
catch (OptionsValidationException ex)
{
    Console.Error.WriteLine("Challenger SIEM agent configuration is invalid:");
    foreach (var failure in ex.Failures)
    {
        Console.Error.WriteLine($"- {failure}");
    }

    Console.Error.WriteLine();
    Console.Error.WriteLine("Create one of these config files:");
    Console.Error.WriteLine($"- {executableDirectoryConfigPath}");
    Console.Error.WriteLine($"- {defaultConfigPath}");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Or set CHALLENGER_SIEM_AGENT_CONFIG to a full agentsettings.json path.");
    Environment.ExitCode = 2;
}
