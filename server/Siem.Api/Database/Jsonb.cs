using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

internal static class Jsonb
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static void Add(NpgsqlCommand command, string name, object? value)
    {
        var parameter = command.Parameters.Add(name, NpgsqlDbType.Jsonb);
        parameter.Value = value is null ? DBNull.Value : JsonSerializer.Serialize(value, JsonOptions);
    }

    public static T? Read<T>(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        if (reader.IsDBNull(ordinal))
        {
            return default;
        }

        return JsonSerializer.Deserialize<T>(reader.GetString(ordinal), JsonOptions);
    }
}
