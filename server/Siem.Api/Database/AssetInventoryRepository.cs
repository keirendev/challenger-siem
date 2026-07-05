using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed class AssetInventoryRepository(NpgsqlDataSource dataSource)
{
    public async Task<IReadOnlyList<AssetInventorySnapshot>> SearchAsync(string? agentId, string? snapshotType, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select agent_id, hostname, snapshot_type, collected_at, items, summary
            from asset_inventory_snapshots
            """;
        var where = new List<string>();
        if (!string.IsNullOrWhiteSpace(agentId))
        {
            where.Add("agent_id = @agent_id");
            command.Parameters.AddWithValue("agent_id", agentId);
        }

        if (!string.IsNullOrWhiteSpace(snapshotType))
        {
            where.Add("snapshot_type = @snapshot_type");
            command.Parameters.AddWithValue("snapshot_type", snapshotType);
        }

        if (where.Count > 0)
        {
            command.CommandText += " where " + string.Join(" and ", where);
        }

        command.CommandText += " order by collected_at desc limit 200;";
        var results = new List<AssetInventorySnapshot>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new AssetInventorySnapshot
            {
                AgentId = reader.GetString(reader.GetOrdinal("agent_id")),
                Hostname = reader.GetString(reader.GetOrdinal("hostname")),
                SnapshotType = reader.GetString(reader.GetOrdinal("snapshot_type")),
                CollectedAt = ReadDateTimeOffset(reader, "collected_at"),
                Items = JsonSerializer.Deserialize<IReadOnlyList<InventoryItem>>(reader.GetString(reader.GetOrdinal("items")), new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? Array.Empty<InventoryItem>(),
                Summary = JsonSerializer.Deserialize<IReadOnlyDictionary<string, string>>(reader.GetString(reader.GetOrdinal("summary")), new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            });
        }

        return results;
    }

    public async Task StoreAsync(AssetInventorySnapshot snapshot, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into asset_inventory_snapshots (agent_id, hostname, snapshot_type, collected_at, items, summary)
            values (@agent_id, @hostname, @snapshot_type, @collected_at, @items, @summary);
            """;
        command.Parameters.AddWithValue("agent_id", snapshot.AgentId);
        command.Parameters.AddWithValue("hostname", snapshot.Hostname);
        command.Parameters.AddWithValue("snapshot_type", snapshot.SnapshotType);
        command.Parameters.AddWithValue("collected_at", snapshot.CollectedAt.ToUniversalTime());
        var items = command.Parameters.Add("items", NpgsqlDbType.Jsonb);
        items.Value = JsonSerializer.Serialize(snapshot.Items, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var summary = command.Parameters.Add("summary", NpgsqlDbType.Jsonb);
        summary.Value = JsonSerializer.Serialize(snapshot.Summary, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static DateTimeOffset ReadDateTimeOffset(NpgsqlDataReader reader, string columnName)
    {
        var value = reader.GetValue(reader.GetOrdinal(columnName));
        return value switch
        {
            DateTimeOffset dateTimeOffset => dateTimeOffset.ToUniversalTime(),
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => throw new InvalidOperationException("Column did not contain a timestamp value.")
        };
    }
}
