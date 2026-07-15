using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed record BoundedInvestigationGraphCollectionState(int Returned, bool Truncated);

public sealed record BoundedInvestigationGraphDetailResult(
    InvestigationGraphDetail Detail,
    int NestedLimit,
    int ReturnedNestedRecords,
    bool Truncated,
    IReadOnlyDictionary<string, BoundedInvestigationGraphCollectionState> Collections);

public sealed class InvestigationGraphRepository(NpgsqlDataSource dataSource)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly HashSet<string> AllowedNodeTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "agent", "host", "user", "process", "ip", "domain", "file", "registry_key", "service", "event", "alert", "detection_rule", "source_health", "note", "custom"
    };
    private static readonly HashSet<string> AllowedEdgeTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "observed_on", "generated", "parent_of", "communicated_with", "authenticated_as", "touched_file", "modified_registry", "evidence_for", "related_to", "annotates"
    };

    public async Task<IReadOnlyList<InvestigationGraphSummary>> ListAsync(string? status, CancellationToken cancellationToken, int limit = 100, int offset = 0)
    {
        var clampedLimit = Math.Clamp(limit, 1, 100);
        var clampedOffset = Math.Max(0, offset);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var normalizedStatus = NormalizeStatusFilter(status);
        command.CommandText = GraphSelectSql + (normalizedStatus == "all" ? "" : " where g.status = @status") + " order by g.updated_at desc limit @limit offset @offset;";
        if (normalizedStatus != "all") command.Parameters.AddWithValue("status", normalizedStatus);
        command.Parameters.AddWithValue("limit", clampedLimit);
        command.Parameters.AddWithValue("offset", clampedOffset);
        var results = new List<InvestigationGraphSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(ReadSummary(reader));
        return results;
    }

    public async Task<InvestigationGraphSummary> CreateAsync(InvestigationGraphCreateRequest request, string? actor, CancellationToken cancellationToken)
    {
        ValidateGraph(request.Title, request.Description, request.Tags);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var graphId = Guid.NewGuid();
        InvestigationGraphSummary summary;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into investigation_graphs (graph_id, title, description, owner, tags)
                values (@graph_id, @title, @description, @owner, @tags)
                returning graph_id, title, description, status, owner, tags, version, created_at, updated_at, 0::int as node_count, 0::int as edge_count;
                """;
            command.Parameters.AddWithValue("graph_id", graphId);
            command.Parameters.AddWithValue("title", request.Title.Trim());
            command.Parameters.AddWithValue("description", StringOrDbNull(request.Description));
            command.Parameters.AddWithValue("owner", StringOrDbNull(request.Owner));
            command.Parameters.AddWithValue("tags", NormalizeTags(request.Tags));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            await reader.ReadAsync(cancellationToken);
            summary = ReadSummary(reader);
        }
        await AddAuditAsync(connection, transaction, graphId, "create", actor, "Created investigation graph.", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return summary;
    }

    public async Task<InvestigationGraphSummary?> UpdateAsync(Guid graphId, InvestigationGraphUpdateRequest request, string? actor, CancellationToken cancellationToken)
    {
        ValidateGraph(request.Title, request.Description, request.Tags);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        InvestigationGraphSummary? summary = null;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                update investigation_graphs
                set title = @title, description = @description, owner = @owner, tags = @tags, version = version + 1, updated_at = now()
                where graph_id = @graph_id and version = @expected_version and status <> 'archived'
                returning graph_id, title, description, status, owner, tags, version, created_at, updated_at,
                    (select count(*)::int from investigation_graph_nodes where graph_id = @graph_id and status = 'active') as node_count,
                    (select count(*)::int from investigation_graph_edges where graph_id = @graph_id and status = 'active') as edge_count;
                """;
            command.Parameters.AddWithValue("graph_id", graphId);
            command.Parameters.AddWithValue("expected_version", request.ExpectedVersion);
            command.Parameters.AddWithValue("title", request.Title.Trim());
            command.Parameters.AddWithValue("description", StringOrDbNull(request.Description));
            command.Parameters.AddWithValue("owner", StringOrDbNull(request.Owner));
            command.Parameters.AddWithValue("tags", NormalizeTags(request.Tags));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken)) summary = ReadSummary(reader);
        }
        if (summary is not null) await AddAuditAsync(connection, transaction, graphId, "update", actor, "Updated graph metadata.", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return summary;
    }

    public async Task<InvestigationGraphDetail?> GetDetailAsync(Guid graphId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var summary = await GetSummaryAsync(connection, graphId, cancellationToken);
        if (summary is null) return null;
        var nodes = await GetNodesAsync(connection, graphId, null, cancellationToken);
        var edges = await GetEdgesAsync(connection, graphId, null, cancellationToken);
        var proposals = await GetProposalsAsync(connection, graphId, 25, cancellationToken);
        return new InvestigationGraphDetail { Graph = summary, Nodes = nodes, Edges = edges, Proposals = proposals };
    }

    public async Task<BoundedInvestigationGraphDetailResult?> GetBoundedDetailAsync(
        Guid graphId,
        int nestedLimit,
        CancellationToken cancellationToken)
    {
        if (nestedLimit is < 1 or > 100)
        {
            throw new ArgumentException("Nested investigation graph record limit must be between 1 and 100.", nameof(nestedLimit));
        }

        var fetchLimit = nestedLimit + 1;
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var summary = await GetSummaryAsync(connection, graphId, cancellationToken);
        if (summary is null) return null;
        var nodes = await GetNodesAsync(connection, graphId, fetchLimit, cancellationToken);
        var edges = await GetEdgesAsync(connection, graphId, fetchLimit, cancellationToken);
        var proposals = await GetProposalsAsync(connection, graphId, fetchLimit, cancellationToken);
        var collections = new Dictionary<string, BoundedInvestigationGraphCollectionState>(StringComparer.Ordinal)
        {
            ["nodes"] = State(nodes, nestedLimit),
            ["edges"] = State(edges, nestedLimit),
            ["proposals"] = State(proposals, nestedLimit)
        };
        var detail = new InvestigationGraphDetail
        {
            Graph = summary,
            Nodes = nodes.Take(nestedLimit).ToArray(),
            Edges = edges.Take(nestedLimit).ToArray(),
            Proposals = proposals.Take(nestedLimit).ToArray()
        };
        var returned = collections.Values.Sum(item => item.Returned);
        return new BoundedInvestigationGraphDetailResult(
            detail,
            nestedLimit,
            returned,
            collections.Values.Any(item => item.Truncated),
            collections);
    }

    public async Task<InvestigationGraphSummary?> ArchiveAsync(Guid graphId, string? actor, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        InvestigationGraphSummary? summary = null;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                update investigation_graphs set status = 'archived', version = version + 1, updated_at = now()
                where graph_id = @graph_id
                returning graph_id, title, description, status, owner, tags, version, created_at, updated_at,
                    (select count(*)::int from investigation_graph_nodes where graph_id = @graph_id and status = 'active') as node_count,
                    (select count(*)::int from investigation_graph_edges where graph_id = @graph_id and status = 'active') as edge_count;
                """;
            command.Parameters.AddWithValue("graph_id", graphId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken)) summary = ReadSummary(reader);
        }
        if (summary is not null) await AddAuditAsync(connection, transaction, graphId, "archive", actor, "Archived investigation graph.", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return summary;
    }

    public async Task<InvestigationGraphNode?> AddNodeAsync(Guid graphId, InvestigationGraphNodeRequest request, string? actor, CancellationToken cancellationToken)
    {
        ValidateNode(request);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var activeNodes = await CountAsync(connection, "investigation_graph_nodes", graphId, cancellationToken);
        if (activeNodes >= InvestigationGraphLimits.MaxNodes) throw new InvalidOperationException("Graph node limit reached.");
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var node = await InsertNodeAsync(connection, transaction, graphId, request, cancellationToken);
        await TouchGraphAsync(connection, transaction, graphId, cancellationToken);
        await AddAuditAsync(connection, transaction, graphId, "add_node", actor, $"Added node {node.Label}.", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return node;
    }

    public async Task<InvestigationGraphEdge?> AddEdgeAsync(Guid graphId, InvestigationGraphEdgeRequest request, string? actor, CancellationToken cancellationToken)
    {
        ValidateEdge(request);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var activeEdges = await CountAsync(connection, "investigation_graph_edges", graphId, cancellationToken);
        if (activeEdges >= InvestigationGraphLimits.MaxEdges) throw new InvalidOperationException("Graph edge limit reached.");
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var edge = await InsertEdgeAsync(connection, transaction, graphId, request, cancellationToken);
        await TouchGraphAsync(connection, transaction, graphId, cancellationToken);
        await AddAuditAsync(connection, transaction, graphId, "add_edge", actor, $"Added edge {edge.EdgeType}.", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return edge;
    }

    public async Task<InvestigationGraphProposal> CreateSocAgentProposalAsync(Guid graphId, string instruction, string? actor, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(instruction) || instruction.Length > InvestigationGraphLimits.MaxNotesLength) throw new ArgumentException("Instruction is required and bounded.");
        var node = new InvestigationGraphNodeRequest { NodeType = "note", Label = "soc-agent proposal", Notes = instruction.Trim() };
        var proposalId = Guid.NewGuid();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into investigation_graph_proposals (proposal_id, graph_id, instruction, rationale, proposed_nodes, proposed_edges, created_by)
            values (@proposal_id, @graph_id, @instruction, @rationale, @proposed_nodes, '[]'::jsonb, @created_by)
            returning proposal_id, graph_id, status, instruction, rationale, proposed_nodes, proposed_edges, created_by, approved_by, created_at, applied_at;
            """;
        command.Parameters.AddWithValue("proposal_id", proposalId);
        command.Parameters.AddWithValue("graph_id", graphId);
        command.Parameters.AddWithValue("instruction", instruction.Trim());
        command.Parameters.AddWithValue("rationale", "soc-agent proposed a bounded note node. Review and apply explicitly to mutate the graph.");
        AddJsonb(command, "proposed_nodes", new[] { node });
        command.Parameters.AddWithValue("created_by", StringOrDbNull(actor));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return ReadProposal(reader);
    }

    public async Task<InvestigationGraphProposal?> ApplyProposalAsync(Guid graphId, Guid proposalId, string? actor, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        InvestigationGraphProposal? proposal;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "select proposal_id, graph_id, status, instruction, rationale, proposed_nodes, proposed_edges, created_by, approved_by, created_at, applied_at from investigation_graph_proposals where graph_id = @graph_id and proposal_id = @proposal_id for update;";
            command.Parameters.AddWithValue("graph_id", graphId);
            command.Parameters.AddWithValue("proposal_id", proposalId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            proposal = await reader.ReadAsync(cancellationToken) ? ReadProposal(reader) : null;
        }
        if (proposal is null || proposal.Status != "pending") { await transaction.RollbackAsync(cancellationToken); return proposal; }
        foreach (var node in proposal.ProposedNodes) await InsertNodeAsync(connection, transaction, graphId, node, cancellationToken);
        foreach (var edge in proposal.ProposedEdges) await InsertEdgeAsync(connection, transaction, graphId, edge, cancellationToken);
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "update investigation_graph_proposals set status = 'applied', approved_by = @actor, applied_at = now() where proposal_id = @proposal_id;";
            update.Parameters.AddWithValue("actor", StringOrDbNull(actor));
            update.Parameters.AddWithValue("proposal_id", proposalId);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        await TouchGraphAsync(connection, transaction, graphId, cancellationToken);
        await AddAuditAsync(connection, transaction, graphId, "apply_proposal", actor, "Applied soc-agent graph proposal.", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return (await GetDetailAsync(graphId, cancellationToken))?.Proposals.FirstOrDefault(p => p.ProposalId == proposalId);
    }

    private const string GraphSelectSql = """
        select g.graph_id, g.title, g.description, g.status, g.owner, g.tags, g.version, g.created_at, g.updated_at,
            coalesce(n.node_count, 0)::int as node_count,
            coalesce(e.edge_count, 0)::int as edge_count
        from investigation_graphs g
        left join lateral (select count(*)::int as node_count from investigation_graph_nodes where graph_id = g.graph_id and status = 'active') n on true
        left join lateral (select count(*)::int as edge_count from investigation_graph_edges where graph_id = g.graph_id and status = 'active') e on true
        """;

    private static async Task<InvestigationGraphSummary?> GetSummaryAsync(NpgsqlConnection connection, Guid graphId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = GraphSelectSql + " where g.graph_id = @graph_id;";
        command.Parameters.AddWithValue("graph_id", graphId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSummary(reader) : null;
    }

    private static async Task<IReadOnlyList<InvestigationGraphNode>> GetNodesAsync(NpgsqlConnection connection, Guid graphId, int? limit, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select node_id, node_type, label, reference_kind, reference_id, link_url, notes, metadata, x, y, status from investigation_graph_nodes where graph_id = @graph_id order by created_at asc";
        command.Parameters.AddWithValue("graph_id", graphId);
        AddOptionalLimit(command, limit);
        var results = new List<InvestigationGraphNode>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(ReadNode(reader));
        return results;
    }

    private static async Task<IReadOnlyList<InvestigationGraphEdge>> GetEdgesAsync(NpgsqlConnection connection, Guid graphId, int? limit, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select edge_id, source_node_id, target_node_id, edge_type, label, notes, metadata, status from investigation_graph_edges where graph_id = @graph_id order by created_at asc";
        command.Parameters.AddWithValue("graph_id", graphId);
        AddOptionalLimit(command, limit);
        var results = new List<InvestigationGraphEdge>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(ReadEdge(reader));
        return results;
    }

    private static async Task<IReadOnlyList<InvestigationGraphProposal>> GetProposalsAsync(NpgsqlConnection connection, Guid graphId, int limit, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select proposal_id, graph_id, status, instruction, rationale, proposed_nodes, proposed_edges, created_by, approved_by, created_at, applied_at from investigation_graph_proposals where graph_id = @graph_id order by created_at desc limit @nested_limit;";
        command.Parameters.AddWithValue("graph_id", graphId);
        command.Parameters.AddWithValue("nested_limit", limit);
        var results = new List<InvestigationGraphProposal>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(ReadProposal(reader));
        return results;
    }

    private static BoundedInvestigationGraphCollectionState State<T>(IReadOnlyCollection<T> rows, int limit) =>
        new(Math.Min(rows.Count, limit), rows.Count > limit);

    private static void AddOptionalLimit(NpgsqlCommand command, int? limit)
    {
        if (limit.HasValue)
        {
            command.CommandText += " limit @nested_limit;";
            command.Parameters.AddWithValue("nested_limit", limit.Value);
            return;
        }

        command.CommandText += ";";
    }

    private static async Task<InvestigationGraphNode> InsertNodeAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid graphId, InvestigationGraphNodeRequest request, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            insert into investigation_graph_nodes (node_id, graph_id, node_type, label, reference_kind, reference_id, link_url, notes, metadata, x, y)
            values (@node_id, @graph_id, @node_type, @label, @reference_kind, @reference_id, @link_url, @notes, @metadata, @x, @y)
            returning node_id, node_type, label, reference_kind, reference_id, link_url, notes, metadata, x, y, status;
            """;
        command.Parameters.AddWithValue("node_id", Guid.NewGuid()); command.Parameters.AddWithValue("graph_id", graphId); command.Parameters.AddWithValue("node_type", NormalizeType(request.NodeType, AllowedNodeTypes, "custom")); command.Parameters.AddWithValue("label", request.Label.Trim()); command.Parameters.AddWithValue("reference_kind", StringOrDbNull(request.ReferenceKind)); command.Parameters.AddWithValue("reference_id", StringOrDbNull(request.ReferenceId)); command.Parameters.AddWithValue("link_url", StringOrDbNull(request.LinkUrl)); command.Parameters.AddWithValue("notes", StringOrDbNull(request.Notes)); AddJsonb(command, "metadata", request.Metadata); command.Parameters.AddWithValue("x", request.X.HasValue ? request.X.Value : (object)DBNull.Value); command.Parameters.AddWithValue("y", request.Y.HasValue ? request.Y.Value : (object)DBNull.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken); await reader.ReadAsync(cancellationToken); return ReadNode(reader);
    }

    private static async Task<InvestigationGraphEdge> InsertEdgeAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid graphId, InvestigationGraphEdgeRequest request, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            insert into investigation_graph_edges (edge_id, graph_id, source_node_id, target_node_id, edge_type, label, notes, metadata)
            values (@edge_id, @graph_id, @source_node_id, @target_node_id, @edge_type, @label, @notes, @metadata)
            returning edge_id, source_node_id, target_node_id, edge_type, label, notes, metadata, status;
            """;
        command.Parameters.AddWithValue("edge_id", Guid.NewGuid()); command.Parameters.AddWithValue("graph_id", graphId); command.Parameters.AddWithValue("source_node_id", request.SourceNodeId); command.Parameters.AddWithValue("target_node_id", request.TargetNodeId); command.Parameters.AddWithValue("edge_type", NormalizeType(request.EdgeType, AllowedEdgeTypes, "related_to")); command.Parameters.AddWithValue("label", StringOrDbNull(request.Label)); command.Parameters.AddWithValue("notes", StringOrDbNull(request.Notes)); AddJsonb(command, "metadata", request.Metadata);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken); await reader.ReadAsync(cancellationToken); return ReadEdge(reader);
    }

    private static async Task<int> CountAsync(NpgsqlConnection connection, string table, Guid graphId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.CommandText = $"select count(*)::int from {table} where graph_id = @graph_id and status = 'active';"; command.Parameters.AddWithValue("graph_id", graphId); return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
    }
    private static async Task TouchGraphAsync(NpgsqlConnection c, NpgsqlTransaction t, Guid graphId, CancellationToken ct) { await using var cmd = c.CreateCommand(); cmd.Transaction = t; cmd.CommandText = "update investigation_graphs set version = version + 1, updated_at = now() where graph_id = @graph_id;"; cmd.Parameters.AddWithValue("graph_id", graphId); await cmd.ExecuteNonQueryAsync(ct); }
    private static async Task AddAuditAsync(NpgsqlConnection c, NpgsqlTransaction t, Guid graphId, string action, string? actor, string summary, CancellationToken ct) { await using var cmd = c.CreateCommand(); cmd.Transaction = t; cmd.CommandText = "insert into investigation_graph_audit (graph_id, action, actor, summary) values (@graph_id, @action, @actor, @summary);"; cmd.Parameters.AddWithValue("graph_id", graphId); cmd.Parameters.AddWithValue("action", action); cmd.Parameters.AddWithValue("actor", StringOrDbNull(actor)); cmd.Parameters.AddWithValue("summary", summary); await cmd.ExecuteNonQueryAsync(ct); }

    private static void ValidateGraph(string title, string? description, IReadOnlyList<string> tags) { if (string.IsNullOrWhiteSpace(title) || title.Length > InvestigationGraphLimits.MaxTitleLength) throw new ArgumentException("Graph title is required and bounded."); if (description?.Length > InvestigationGraphLimits.MaxDescriptionLength) throw new ArgumentException("Graph description is too long."); if (tags.Count > InvestigationGraphLimits.MaxTags) throw new ArgumentException("Too many tags."); }
    private static void ValidateNode(InvestigationGraphNodeRequest request) { if (string.IsNullOrWhiteSpace(request.Label) || request.Label.Length > InvestigationGraphLimits.MaxLabelLength) throw new ArgumentException("Node label is required and bounded."); if (request.Notes?.Length > InvestigationGraphLimits.MaxNotesLength) throw new ArgumentException("Node notes are too long."); }
    private static void ValidateEdge(InvestigationGraphEdgeRequest request) { if (request.SourceNodeId == Guid.Empty || request.TargetNodeId == Guid.Empty || request.SourceNodeId == request.TargetNodeId) throw new ArgumentException("Edge requires two different nodes."); if (request.Notes?.Length > InvestigationGraphLimits.MaxNotesLength) throw new ArgumentException("Edge notes are too long."); }
    private static string NormalizeStatusFilter(string? value) => value?.Trim().ToLowerInvariant() is "all" ? "all" : value?.Trim().ToLowerInvariant() is "archived" ? "archived" : "active";
    private static string NormalizeType(string? value, HashSet<string> allowed, string fallback) { var candidate = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim().ToLowerInvariant(); return allowed.Contains(candidate) ? candidate : fallback; }
    private static string[] NormalizeTags(IReadOnlyList<string> tags) => tags.Select(t => t.Trim().ToLowerInvariant()).Where(t => t.Length > 0).Distinct().Take(InvestigationGraphLimits.MaxTags).ToArray();
    private static object StringOrDbNull(string? value) => string.IsNullOrWhiteSpace(value) ? DBNull.Value : value.Trim();
    private static void AddJsonb(NpgsqlCommand command, string name, object? value) { var parameter = command.Parameters.Add(name, NpgsqlDbType.Jsonb); parameter.Value = value is null ? "{}" : JsonSerializer.Serialize(value, JsonOptions); }
    private static JsonElement? ReadJson(NpgsqlDataReader reader, string column) { var ordinal = reader.GetOrdinal(column); if (reader.IsDBNull(ordinal)) return null; using var document = JsonDocument.Parse(reader.GetString(ordinal)); return document.RootElement.Clone(); }
    private static IReadOnlyList<T> ReadJsonList<T>(NpgsqlDataReader reader, string column) { var ordinal = reader.GetOrdinal(column); if (reader.IsDBNull(ordinal)) return Array.Empty<T>(); return JsonSerializer.Deserialize<IReadOnlyList<T>>(reader.GetString(ordinal), JsonOptions) ?? Array.Empty<T>(); }
    private static string? ReadNullableString(NpgsqlDataReader reader, string column) { var ordinal = reader.GetOrdinal(column); return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal); }
    private static decimal? ReadNullableDecimal(NpgsqlDataReader reader, string column) { var ordinal = reader.GetOrdinal(column); return reader.IsDBNull(ordinal) ? null : reader.GetDecimal(ordinal); }
    private static DateTimeOffset ReadDate(NpgsqlDataReader reader, string column) { var value = reader.GetValue(reader.GetOrdinal(column)); return value is DateTimeOffset dto ? dto.ToUniversalTime() : new DateTimeOffset(DateTime.SpecifyKind((DateTime)value, DateTimeKind.Utc)); }
    private static InvestigationGraphSummary ReadSummary(NpgsqlDataReader r) => new() { GraphId = r.GetGuid(r.GetOrdinal("graph_id")), Title = r.GetString(r.GetOrdinal("title")), Description = ReadNullableString(r, "description"), Status = r.GetString(r.GetOrdinal("status")), Owner = ReadNullableString(r, "owner"), Tags = r.GetFieldValue<string[]>(r.GetOrdinal("tags")), Version = r.GetInt32(r.GetOrdinal("version")), CreatedAt = ReadDate(r, "created_at"), UpdatedAt = ReadDate(r, "updated_at"), NodeCount = r.GetInt32(r.GetOrdinal("node_count")), EdgeCount = r.GetInt32(r.GetOrdinal("edge_count")) };
    private static InvestigationGraphNode ReadNode(NpgsqlDataReader r) => new() { NodeId = r.GetGuid(r.GetOrdinal("node_id")), NodeType = r.GetString(r.GetOrdinal("node_type")), Label = r.GetString(r.GetOrdinal("label")), ReferenceKind = ReadNullableString(r, "reference_kind"), ReferenceId = ReadNullableString(r, "reference_id"), LinkUrl = ReadNullableString(r, "link_url"), Notes = ReadNullableString(r, "notes"), Metadata = ReadJson(r, "metadata"), X = ReadNullableDecimal(r, "x"), Y = ReadNullableDecimal(r, "y"), Status = r.GetString(r.GetOrdinal("status")) };
    private static InvestigationGraphEdge ReadEdge(NpgsqlDataReader r) => new() { EdgeId = r.GetGuid(r.GetOrdinal("edge_id")), SourceNodeId = r.GetGuid(r.GetOrdinal("source_node_id")), TargetNodeId = r.GetGuid(r.GetOrdinal("target_node_id")), EdgeType = r.GetString(r.GetOrdinal("edge_type")), Label = ReadNullableString(r, "label"), Notes = ReadNullableString(r, "notes"), Metadata = ReadJson(r, "metadata"), Status = r.GetString(r.GetOrdinal("status")) };
    private static InvestigationGraphProposal ReadProposal(NpgsqlDataReader r) => new() { ProposalId = r.GetGuid(r.GetOrdinal("proposal_id")), GraphId = r.GetGuid(r.GetOrdinal("graph_id")), Status = r.GetString(r.GetOrdinal("status")), Instruction = r.GetString(r.GetOrdinal("instruction")), Rationale = r.GetString(r.GetOrdinal("rationale")), ProposedNodes = ReadJsonList<InvestigationGraphNodeRequest>(r, "proposed_nodes"), ProposedEdges = ReadJsonList<InvestigationGraphEdgeRequest>(r, "proposed_edges"), CreatedBy = ReadNullableString(r, "created_by"), ApprovedBy = ReadNullableString(r, "approved_by"), CreatedAt = ReadDate(r, "created_at"), AppliedAt = r.IsDBNull(r.GetOrdinal("applied_at")) ? null : ReadDate(r, "applied_at") };
}
