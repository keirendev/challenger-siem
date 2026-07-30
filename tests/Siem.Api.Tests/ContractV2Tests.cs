using System.Text.Json;
using System.Text.Json.Nodes;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Contracts.V2;
using Json.Schema;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class ContractV2Tests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly string FixturesRoot = Path.Combine(RepositoryRoot, "tests", "ContractFixtures", "v2");
    private static readonly string SchemasRoot = Path.Combine(RepositoryRoot, "contracts", "v2");

    [Theory]
    [InlineData("linux-registration.synthetic.json", "agent-registration.schema.json", typeof(AgentRegistrationRequest))]
    [InlineData("linux-heartbeat.synthetic.json", "heartbeat.schema.json", typeof(HeartbeatRequest))]
    [InlineData("linux-l2-heartbeat.synthetic.json", "heartbeat.schema.json", typeof(HeartbeatRequest))]
    [InlineData("linux-ingest.synthetic.json", "ingest-batch.schema.json", typeof(IngestBatchRequest))]
    public void LinuxFixturesValidateAgainstV2AndDeserialize(string fixtureName, string schemaName, Type contractType)
    {
        var json = File.ReadAllText(Path.Combine(FixturesRoot, fixtureName));
        var instance = JsonNode.Parse(json) ?? throw new InvalidOperationException("Fixture parsed to null.");

        AssertSchemaValid(schemaName, instance);
        Assert.NotNull(JsonSerializer.Deserialize(json, contractType, JsonOptions));
    }

    [Fact]
    public void V2RuntimeContractsAcceptCanonicalLinuxFixtures()
    {
        var registration = Read<AgentRegistrationRequest>("linux-registration.synthetic.json");
        var heartbeat = Read<HeartbeatRequest>("linux-heartbeat.synthetic.json");
        var batch = Read<IngestBatchRequest>("linux-ingest.synthetic.json");

        Assert.Empty(RequestValidation.ValidateRegistration(registration));
        Assert.Empty(RequestValidation.ValidateHeartbeat(heartbeat));
        Assert.Empty(RequestValidation.ValidateBatch(batch, 500));
        Assert.All(batch.Events, item => Assert.Equal(TelemetryPlatforms.Linux, item.Platform));
    }

    [Fact]
    public void V2RegistrationSchemaRejectsAnyNonLinuxPlatform()
    {
        var instance = JsonNode.Parse(File.ReadAllText(Path.Combine(FixturesRoot, "linux-registration.synthetic.json")))!;
        instance["platform"] = "unsupported-platform";

        Assert.False(Evaluate("agent-registration.schema.json", instance).IsValid);
    }

    [Fact]
    public void EveryPublishedV2SchemaParsesAndUsesTheV2Identifier()
    {
        foreach (var path in Directory.GetFiles(SchemasRoot, "*.schema.json"))
        {
            var document = JsonNode.Parse(File.ReadAllText(path))?.AsObject();
            Assert.NotNull(document);
            Assert.Contains("/contracts/v2/", document!["$id"]?.GetValue<string>(), StringComparison.Ordinal);
            _ = JsonSchema.FromText(document.ToJsonString());
        }
    }

    private static T Read<T>(string fixtureName) where T : notnull =>
        JsonSerializer.Deserialize<T>(File.ReadAllText(Path.Combine(FixturesRoot, fixtureName)), JsonOptions)
        ?? throw new InvalidOperationException($"Fixture {fixtureName} deserialized to null.");

    private static void AssertSchemaValid(string schemaName, JsonNode instance)
    {
        var result = Evaluate(schemaName, instance);
        Assert.True(result.IsValid, $"{schemaName} validation failed: {JsonSerializer.Serialize(result)}");
    }

    private static EvaluationResults Evaluate(string schemaName, JsonNode instance)
    {
        var options = new EvaluationOptions
        {
            OutputFormat = OutputFormat.List,
            RequireFormatValidation = true
        };
        foreach (var path in Directory.GetFiles(SchemasRoot, "*.schema.json"))
        {
            options.SchemaRegistry.Register(JsonSchema.FromText(File.ReadAllText(path)));
        }

        return JsonSchema.FromText(File.ReadAllText(Path.Combine(SchemasRoot, schemaName))).Evaluate(instance, options);
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln"))) return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("Could not locate the repository root.");
    }
}
