using System.Text.Json;
using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public static class InvestigationGraphLimits
{
    public const int MaxTitleLength = 160;
    public const int MaxDescriptionLength = 4000;
    public const int MaxLabelLength = 200;
    public const int MaxNotesLength = 4000;
    public const int MaxTags = 20;
    public const int MaxNodes = 200;
    public const int MaxEdges = 400;
}

public sealed record InvestigationGraphSummary
{
    [JsonPropertyName("graph_id")]
    public Guid GraphId { get; init; }

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = "active";

    [JsonPropertyName("owner")]
    public string? Owner { get; init; }

    [JsonPropertyName("tags")]
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();

    [JsonPropertyName("version")]
    public int Version { get; init; }

    [JsonPropertyName("node_count")]
    public int NodeCount { get; init; }

    [JsonPropertyName("edge_count")]
    public int EdgeCount { get; init; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; }

    [JsonPropertyName("updated_at")]
    public DateTimeOffset UpdatedAt { get; init; }
}

public sealed record InvestigationGraphDetail
{
    [JsonPropertyName("graph")]
    public InvestigationGraphSummary Graph { get; init; } = new();

    [JsonPropertyName("nodes")]
    public IReadOnlyList<InvestigationGraphNode> Nodes { get; init; } = Array.Empty<InvestigationGraphNode>();

    [JsonPropertyName("edges")]
    public IReadOnlyList<InvestigationGraphEdge> Edges { get; init; } = Array.Empty<InvestigationGraphEdge>();

    [JsonPropertyName("proposals")]
    public IReadOnlyList<InvestigationGraphProposal> Proposals { get; init; } = Array.Empty<InvestigationGraphProposal>();
}

public sealed record InvestigationGraphNode
{
    [JsonPropertyName("node_id")]
    public Guid NodeId { get; init; }

    [JsonPropertyName("node_type")]
    public string NodeType { get; init; } = "custom";

    [JsonPropertyName("label")]
    public string Label { get; init; } = string.Empty;

    [JsonPropertyName("reference_kind")]
    public string? ReferenceKind { get; init; }

    [JsonPropertyName("reference_id")]
    public string? ReferenceId { get; init; }

    [JsonPropertyName("link_url")]
    public string? LinkUrl { get; init; }

    [JsonPropertyName("notes")]
    public string? Notes { get; init; }

    [JsonPropertyName("metadata")]
    public JsonElement? Metadata { get; init; }

    [JsonPropertyName("x")]
    public decimal? X { get; init; }

    [JsonPropertyName("y")]
    public decimal? Y { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = "active";
}

public sealed record InvestigationGraphEdge
{
    [JsonPropertyName("edge_id")]
    public Guid EdgeId { get; init; }

    [JsonPropertyName("source_node_id")]
    public Guid SourceNodeId { get; init; }

    [JsonPropertyName("target_node_id")]
    public Guid TargetNodeId { get; init; }

    [JsonPropertyName("edge_type")]
    public string EdgeType { get; init; } = "related_to";

    [JsonPropertyName("label")]
    public string? Label { get; init; }

    [JsonPropertyName("notes")]
    public string? Notes { get; init; }

    [JsonPropertyName("metadata")]
    public JsonElement? Metadata { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = "active";
}

public sealed record InvestigationGraphCreateRequest
{
    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("owner")]
    public string? Owner { get; init; }

    [JsonPropertyName("tags")]
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
}

public sealed record InvestigationGraphUpdateRequest
{
    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("owner")]
    public string? Owner { get; init; }

    [JsonPropertyName("tags")]
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();

    [JsonPropertyName("expected_version")]
    public int ExpectedVersion { get; init; }
}

public sealed record InvestigationGraphNodeRequest
{
    [JsonPropertyName("node_type")]
    public string NodeType { get; init; } = "custom";

    [JsonPropertyName("label")]
    public string Label { get; init; } = string.Empty;

    [JsonPropertyName("reference_kind")]
    public string? ReferenceKind { get; init; }

    [JsonPropertyName("reference_id")]
    public string? ReferenceId { get; init; }

    [JsonPropertyName("link_url")]
    public string? LinkUrl { get; init; }

    [JsonPropertyName("notes")]
    public string? Notes { get; init; }

    [JsonPropertyName("metadata")]
    public JsonElement? Metadata { get; init; }

    [JsonPropertyName("x")]
    public decimal? X { get; init; }

    [JsonPropertyName("y")]
    public decimal? Y { get; init; }
}

public sealed record InvestigationGraphEdgeRequest
{
    [JsonPropertyName("source_node_id")]
    public Guid SourceNodeId { get; init; }

    [JsonPropertyName("target_node_id")]
    public Guid TargetNodeId { get; init; }

    [JsonPropertyName("edge_type")]
    public string EdgeType { get; init; } = "related_to";

    [JsonPropertyName("label")]
    public string? Label { get; init; }

    [JsonPropertyName("notes")]
    public string? Notes { get; init; }

    [JsonPropertyName("metadata")]
    public JsonElement? Metadata { get; init; }
}

public sealed record InvestigationGraphProposal
{
    [JsonPropertyName("proposal_id")]
    public Guid ProposalId { get; init; }

    [JsonPropertyName("graph_id")]
    public Guid GraphId { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = "pending";

    [JsonPropertyName("instruction")]
    public string Instruction { get; init; } = string.Empty;

    [JsonPropertyName("rationale")]
    public string Rationale { get; init; } = string.Empty;

    [JsonPropertyName("proposed_nodes")]
    public IReadOnlyList<InvestigationGraphNodeRequest> ProposedNodes { get; init; } = Array.Empty<InvestigationGraphNodeRequest>();

    [JsonPropertyName("proposed_edges")]
    public IReadOnlyList<InvestigationGraphEdgeRequest> ProposedEdges { get; init; } = Array.Empty<InvestigationGraphEdgeRequest>();

    [JsonPropertyName("created_by")]
    public string? CreatedBy { get; init; }

    [JsonPropertyName("approved_by")]
    public string? ApprovedBy { get; init; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; }

    [JsonPropertyName("applied_at")]
    public DateTimeOffset? AppliedAt { get; init; }
}

public sealed record InvestigationGraphProposalRequest
{
    [JsonPropertyName("instruction")]
    public string Instruction { get; init; } = string.Empty;
}
