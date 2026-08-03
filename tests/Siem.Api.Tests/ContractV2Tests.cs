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
    public void NetworkGeographyFixtureValidatesAndDeserializes()
    {
        var json = File.ReadAllText(Path.Combine(FixturesRoot, "network-geography.synthetic.json"));
        AssertSchemaValid("network-geography.schema.json", JsonNode.Parse(json)!);
        Assert.NotNull(JsonSerializer.Deserialize<NetworkGeographyResponse>(json, JsonOptions));
    }

    [Fact]
    public void V2RegistrationSchemaRejectsAnyNonLinuxPlatform()
    {
        var instance = JsonNode.Parse(File.ReadAllText(Path.Combine(FixturesRoot, "linux-registration.synthetic.json")))!;
        instance["platform"] = "unsupported-platform";

        Assert.False(Evaluate("agent-registration.schema.json", instance).IsValid);
    }

    [Fact]
    public void InventorySchemaRejectsEveryIncompletePagingMetadataShape()
    {
        static JsonNode Instance(IReadOnlyDictionary<string, string> summary)
        {
            var instance = JsonNode.Parse("""
                {
                  "agent_id": "synthetic-agent",
                  "sent_at": "2026-08-01T12:00:00Z",
                  "snapshots": [{
                    "agent_id": "synthetic-agent",
                    "hostname": "SYNTHETIC-LINUX-01",
                    "snapshot_type": "linux_packages",
                    "collected_at": "2026-08-01T12:00:00Z",
                    "items": [],
                    "summary": {}
                  }]
                }
                """)!;
            var summaryNode = instance["snapshots"]![0]!["summary"]!.AsObject();
            foreach (var pair in summary) summaryNode[pair.Key] = pair.Value;
            return instance;
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["generation_id"] = "synthetic-generation",
            ["page_index"] = "1",
            ["page_count"] = "1",
            ["page_item_count"] = "0",
            ["total_item_count"] = "0",
            ["source_complete"] = "true",
            ["source_truncated"] = "false",
            ["generation_complete"] = "true",
            ["received_page_count"] = "1"
        };

        foreach (var key in AssetInventoryPaging.TransportSummaryKeys)
        {
            Assert.False(
                Evaluate("asset-inventory.schema.json", Instance(new Dictionary<string, string> { [key] = values[key] })).IsValid,
                $"A lone {key} field must trigger the complete paging metadata requirement.");
        }

        Assert.True(Evaluate("asset-inventory.schema.json", Instance(values
            .Where(pair => pair.Key is not "generation_complete" and not "received_page_count")
            .ToDictionary())).IsValid);
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
