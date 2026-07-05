using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed class SocAgentRepository(NpgsqlDataSource dataSource)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

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
        AddJsonb(command, "tool_runs", response.ToolRuns);
        AddJsonb(command, "citations", response.Citations);
        command.Parameters.AddWithValue("context_agent_id", string.IsNullOrWhiteSpace(request.ContextAgentId) ? (object)DBNull.Value : request.ContextAgentId);
        command.Parameters.AddWithValue("context_event_id", request.ContextEventId.HasValue ? request.ContextEventId.Value : (object)DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<SocAgentSessionSummary> CreateSessionAsync(
        string title,
        string provider,
        string model,
        string? contextAgentId,
        Guid? contextEventId,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into soc_agent_sessions (session_id, title, provider, model, status, context_agent_id, context_event_id)
            values (@session_id, @title, @provider, @model, 'open', @context_agent_id, @context_event_id)
            returning
                session_id,
                title,
                provider,
                model,
                status,
                context_agent_id,
                context_event_id,
                created_at,
                updated_at,
                0::int as message_count;
            """;
        command.Parameters.AddWithValue("session_id", Guid.NewGuid());
        command.Parameters.AddWithValue("title", Truncate(Redact(title), 160));
        command.Parameters.AddWithValue("provider", provider);
        command.Parameters.AddWithValue("model", model);
        command.Parameters.AddWithValue("context_agent_id", string.IsNullOrWhiteSpace(contextAgentId) ? (object)DBNull.Value : contextAgentId.Trim());
        command.Parameters.AddWithValue("context_event_id", contextEventId.HasValue ? contextEventId.Value : (object)DBNull.Value);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("soc-agent session creation did not return a row.");
        }

        return ReadSession(reader);
    }

    public async Task<SocAgentSessionSummary?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = SessionSelectSql + " where s.session_id = @session_id;";
        command.Parameters.AddWithValue("session_id", sessionId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSession(reader) : null;
    }

    public async Task<IReadOnlyList<SocAgentSessionSummary>> GetRecentSessionsAsync(
        int limit,
        CancellationToken cancellationToken)
    {
        var clampedLimit = Math.Clamp(limit, 1, 50);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = SessionSelectSql + " order by s.updated_at desc, s.created_at desc limit @limit;";
        command.Parameters.AddWithValue("limit", clampedLimit);

        var sessions = new List<SocAgentSessionSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            sessions.Add(ReadSession(reader));
        }

        return sessions;
    }

    public async Task<IReadOnlyList<SocAgentChatMessageDto>> GetMessagesAsync(
        Guid sessionId,
        int limit,
        CancellationToken cancellationToken)
    {
        var clampedLimit = Math.Clamp(limit, 1, 200);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select
                id,
                session_id,
                role,
                content,
                provider,
                model,
                tool_runs,
                citations,
                error_code,
                created_at
            from soc_agent_messages
            where session_id = @session_id
            order by created_at asc, id asc
            limit @limit;
            """;
        command.Parameters.AddWithValue("session_id", sessionId);
        command.Parameters.AddWithValue("limit", clampedLimit);

        var messages = new List<SocAgentChatMessageDto>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            messages.Add(ReadMessage(reader));
        }

        return messages;
    }

    public async Task<bool> DeleteSessionAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "delete from soc_agent_sessions where session_id = @session_id;";
        command.Parameters.AddWithValue("session_id", sessionId);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<SocAgentChatMessageDto> AddMessageAsync(
        Guid sessionId,
        string role,
        string content,
        string? provider,
        string? model,
        IReadOnlyList<SocAgentToolRunSummary> toolRuns,
        IReadOnlyList<SocAgentCitation> citations,
        string? errorCode,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        SocAgentChatMessageDto message;

        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into soc_agent_messages (session_id, role, content, provider, model, tool_runs, citations, error_code)
                values (@session_id, @role, @content, @provider, @model, @tool_runs, @citations, @error_code)
                returning
                    id,
                    session_id,
                    role,
                    content,
                    provider,
                    model,
                    tool_runs,
                    citations,
                    error_code,
                    created_at;
                """;
            command.Parameters.AddWithValue("session_id", sessionId);
            command.Parameters.AddWithValue("role", role);
            command.Parameters.AddWithValue("content", Truncate(Redact(content), 20000));
            command.Parameters.AddWithValue("provider", string.IsNullOrWhiteSpace(provider) ? (object)DBNull.Value : provider);
            command.Parameters.AddWithValue("model", string.IsNullOrWhiteSpace(model) ? (object)DBNull.Value : model);
            AddJsonb(command, "tool_runs", toolRuns);
            AddJsonb(command, "citations", citations);
            command.Parameters.AddWithValue("error_code", string.IsNullOrWhiteSpace(errorCode) ? (object)DBNull.Value : errorCode);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new InvalidOperationException("soc-agent message insert did not return a row.");
            }

            message = ReadMessage(reader);
        }

        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                update soc_agent_sessions
                set updated_at = now(),
                    status = case when @error_code_present then 'error' else 'open' end
                where session_id = @session_id;
                """;
            update.Parameters.AddWithValue("session_id", sessionId);
            update.Parameters.AddWithValue("error_code_present", !string.IsNullOrWhiteSpace(errorCode));
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return message;
    }

    private const string SessionSelectSql = """
        select
            s.session_id,
            s.title,
            s.provider,
            s.model,
            s.status,
            s.context_agent_id,
            s.context_event_id,
            s.created_at,
            s.updated_at,
            coalesce(m.message_count, 0)::int as message_count
        from soc_agent_sessions s
        left join lateral (
            select count(*)::int as message_count
            from soc_agent_messages
            where session_id = s.session_id
        ) m on true
        """;

    private static SocAgentSessionSummary ReadSession(NpgsqlDataReader reader)
    {
        return new SocAgentSessionSummary
        {
            SessionId = reader.GetGuid(reader.GetOrdinal("session_id")),
            Title = reader.GetString(reader.GetOrdinal("title")),
            Provider = reader.GetString(reader.GetOrdinal("provider")),
            Model = reader.GetString(reader.GetOrdinal("model")),
            Status = reader.GetString(reader.GetOrdinal("status")),
            ContextAgentId = ReadNullableString(reader, "context_agent_id"),
            ContextEventId = ReadNullableGuid(reader, "context_event_id"),
            CreatedAt = ReadDateTimeOffset(reader, "created_at"),
            UpdatedAt = ReadDateTimeOffset(reader, "updated_at"),
            MessageCount = reader.GetInt32(reader.GetOrdinal("message_count"))
        };
    }

    private static SocAgentChatMessageDto ReadMessage(NpgsqlDataReader reader)
    {
        return new SocAgentChatMessageDto
        {
            MessageId = reader.GetInt64(reader.GetOrdinal("id")),
            SessionId = reader.GetGuid(reader.GetOrdinal("session_id")),
            Role = reader.GetString(reader.GetOrdinal("role")),
            Content = reader.GetString(reader.GetOrdinal("content")),
            Provider = ReadNullableString(reader, "provider"),
            Model = ReadNullableString(reader, "model"),
            ToolRuns = ReadJsonList<SocAgentToolRunSummary>(reader, "tool_runs"),
            Citations = ReadJsonList<SocAgentCitation>(reader, "citations"),
            ErrorCode = ReadNullableString(reader, "error_code"),
            CreatedAt = ReadDateTimeOffset(reader, "created_at")
        };
    }

    private static void AddJsonb(NpgsqlCommand command, string name, object? value)
    {
        var parameter = command.Parameters.Add(name, NpgsqlDbType.Jsonb);
        parameter.Value = value is null ? "[]" : JsonSerializer.Serialize(value, JsonOptions);
    }

    private static IReadOnlyList<T> ReadJsonList<T>(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        if (reader.IsDBNull(ordinal))
        {
            return Array.Empty<T>();
        }

        var json = reader.GetString(ordinal);
        return JsonSerializer.Deserialize<IReadOnlyList<T>>(json, JsonOptions) ?? Array.Empty<T>();
    }

    private static string? ReadNullableString(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static Guid? ReadNullableGuid(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetGuid(ordinal);
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

    private static string Redact(string value)
    {
        var withoutBearer = Regex.Replace(value, "Bearer\\s+[A-Za-z0-9._~+/-]+=*", "Bearer <redacted>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return Regex.Replace(withoutBearer, "(?i)(token|password|secret|api[_-]?key)\\s*[:=]\\s*[^\\s,;]+", "$1=<redacted>", RegexOptions.CultureInvariant);
    }

    private static string Truncate(string value, int maxLength) => value.Length <= maxLength ? value : value[..maxLength];
}
