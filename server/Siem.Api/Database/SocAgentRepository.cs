using System.Text.Json;
using System.Text.RegularExpressions;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed class SocAgentRepository(NpgsqlDataSource dataSource)
{
    public async Task SaveTurnAsync(
        SocAgentAskRequest request,
        SocAgentAskResponse response,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into soc_agent_turns (provider, model, question, answer, tool_runs, citations, context_agent_id, context_event_id)
            values (@provider, @model, @question, @answer, @tool_runs, @citations, @context_agent_id, @context_event_id);
            """;
        command.Parameters.AddWithValue("provider", response.Provider);
        command.Parameters.AddWithValue("model", response.Model);
        command.Parameters.AddWithValue("question", Truncate(Redact(request.Question), 4000));
        command.Parameters.AddWithValue("answer", Truncate(Redact(response.Answer), 20000));
        var toolRuns = command.Parameters.Add("tool_runs", NpgsqlDbType.Jsonb);
        toolRuns.Value = JsonSerializer.Serialize(response.ToolRuns, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var citations = command.Parameters.Add("citations", NpgsqlDbType.Jsonb);
        citations.Value = JsonSerializer.Serialize(response.Citations, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        command.Parameters.AddWithValue("context_agent_id", string.IsNullOrWhiteSpace(request.ContextAgentId) ? (object)DBNull.Value : request.ContextAgentId);
        command.Parameters.AddWithValue("context_event_id", request.ContextEventId.HasValue ? request.ContextEventId.Value : (object)DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string Redact(string value)
    {
        var withoutBearer = Regex.Replace(value, "Bearer\\s+[A-Za-z0-9._~+/-]+=*", "Bearer <redacted>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return Regex.Replace(withoutBearer, "(?i)(token|password|secret|api[_-]?key)\\s*[:=]\\s*[^\\s,;]+", "$1=<redacted>", RegexOptions.CultureInvariant);
    }

    private static string Truncate(string value, int maxLength) => value.Length <= maxLength ? value : value[..maxLength];
}
