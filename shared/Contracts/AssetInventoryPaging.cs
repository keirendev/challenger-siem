using System.Globalization;

namespace Challenger.Siem.Contracts.V2;

public sealed record AssetInventoryGenerationStatus(
    string? GenerationId,
    int PageIndex,
    int PageCount,
    int PageItemCount,
    int TotalItemCount,
    int ReceivedPageCount,
    bool SourceComplete,
    bool SourceTruncated,
    bool Complete,
    bool Legacy);

public static class AssetInventoryPaging
{
    public const int MaxItemsPerSource = 4096;
    public const int MaxItemsPerPage = 200;
    public const int MaxPagesPerSource = 32;
    public const int MaxSnapshotsPerRequest = 20;
    public const int MaxSourceOutputBytes = 512 * 1024;
    public const int MaxCollectionBytes = 4 * 1024 * 1024;

    public static readonly IReadOnlySet<string> TransportSummaryKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "generation_id", "page_index", "page_count", "page_item_count", "total_item_count",
        "source_complete", "source_truncated", "generation_complete", "received_page_count"
    };

    public static AssetInventoryGenerationStatus Status(AssetInventorySnapshot snapshot) =>
        Status(new[] { snapshot });

    public static AssetInventoryGenerationStatus Status(IReadOnlyList<AssetInventorySnapshot> pages)
    {
        if (pages.Count == 0) return new(null, 0, 0, 0, 0, 0, false, true, false, false);
        var first = pages[0];
        if (!TryRead(first.Summary, "generation_id", out var generationId))
        {
            var truncated = ReadBoolean(first.Summary, "truncated", false);
            return new(null, 1, 1, first.Items.Count, first.Items.Count, 1, !truncated, truncated, !truncated, true);
        }

        var pageCount = ReadInteger(first.Summary, "page_count", 0);
        var totalItemCount = ReadInteger(first.Summary, "total_item_count", 0);
        var sourceComplete = pages.All(page => ReadBoolean(page.Summary, "source_complete", false));
        var sourceTruncated = pages.Any(page => ReadBoolean(page.Summary, "source_truncated", true));
        var indexes = pages.Select(page => ReadInteger(page.Summary, "page_index", 0))
            .Where(index => index > 0).Distinct().Order().ToArray();
        var consistent = pageCount is >= 1 and <= MaxPagesPerSource
            && pages.All(page => ReadInteger(page.Summary, "page_count", 0) == pageCount)
            && pages.All(page => string.Equals(Read(page.Summary, "generation_id"), generationId, StringComparison.Ordinal))
            && indexes.Length == pageCount
            && indexes.SequenceEqual(Enumerable.Range(1, pageCount));
        var complete = consistent && sourceComplete && !sourceTruncated
            && pages.Sum(page => page.Items.Count) == totalItemCount;
        return new(
            generationId,
            indexes.FirstOrDefault(),
            pageCount,
            pages.Sum(page => page.Items.Count),
            totalItemCount,
            indexes.Length,
            sourceComplete,
            sourceTruncated,
            complete,
            false);
    }

    public static IReadOnlyList<AssetInventorySnapshot> ReassembleLatest(IReadOnlyList<AssetInventorySnapshot> snapshots)
    {
        return snapshots
            .GroupBy(snapshot => (snapshot.AgentId, snapshot.SnapshotType), StringTupleComparer.Instance)
            .Select(group => group
                .GroupBy(GenerationKey, StringComparer.Ordinal)
                .OrderByDescending(generation => generation.Max(page => page.CollectedAt))
                .Select(Reassemble)
                .First())
            .OrderBy(snapshot => snapshot.SnapshotType, StringComparer.Ordinal)
            .ToArray();
    }

    public static AssetInventorySnapshot Reassemble(IGrouping<string, AssetInventorySnapshot> generation) =>
        Reassemble(generation.OrderBy(page => ReadInteger(page.Summary, "page_index", 1)).ToArray());

    public static AssetInventorySnapshot Reassemble(IReadOnlyList<AssetInventorySnapshot> pages)
    {
        if (pages.Count == 0) throw new ArgumentException("At least one inventory page is required.", nameof(pages));
        var first = pages[0];
        var status = Status(pages);
        if (status.Legacy) return first;
        var summary = first.Summary
            .Where(pair => !TransportSummaryKeys.Contains(pair.Key))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        summary["generation_id"] = status.GenerationId!;
        summary["page_index"] = "1";
        summary["page_count"] = status.PageCount.ToString(CultureInfo.InvariantCulture);
        summary["page_item_count"] = pages.Sum(page => page.Items.Count).ToString(CultureInfo.InvariantCulture);
        summary["total_item_count"] = status.TotalItemCount.ToString(CultureInfo.InvariantCulture);
        summary["received_page_count"] = status.ReceivedPageCount.ToString(CultureInfo.InvariantCulture);
        summary["generation_complete"] = status.Complete ? "true" : "false";
        summary["source_complete"] = status.SourceComplete ? "true" : "false";
        summary["source_truncated"] = status.SourceTruncated ? "true" : "false";
        return first with
        {
            Items = pages.SelectMany(page => page.Items).Take(MaxItemsPerSource).ToArray(),
            Summary = summary
        };
    }

    public static string GenerationKey(AssetInventorySnapshot snapshot)
    {
        var generationId = Read(snapshot.Summary, "generation_id");
        return string.IsNullOrWhiteSpace(generationId)
            ? $"legacy:{snapshot.CollectedAt.ToUniversalTime():O}"
            : generationId;
    }

    public static string? Read(IReadOnlyDictionary<string, string> summary, string key) =>
        summary.FirstOrDefault(pair => string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase)).Value;

    public static bool TryRead(IReadOnlyDictionary<string, string> summary, string key, out string value)
    {
        value = Read(summary, key) ?? string.Empty;
        return value.Length > 0;
    }

    public static int ReadInteger(IReadOnlyDictionary<string, string> summary, string key, int fallback) =>
        int.TryParse(Read(summary, key), NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : fallback;

    public static bool ReadBoolean(IReadOnlyDictionary<string, string> summary, string key, bool fallback) =>
        bool.TryParse(Read(summary, key), out var value) ? value : fallback;

    private sealed class StringTupleComparer : IEqualityComparer<(string AgentId, string SnapshotType)>
    {
        public static readonly StringTupleComparer Instance = new();
        public bool Equals((string AgentId, string SnapshotType) x, (string AgentId, string SnapshotType) y) =>
            string.Equals(x.AgentId, y.AgentId, StringComparison.Ordinal) && string.Equals(x.SnapshotType, y.SnapshotType, StringComparison.Ordinal);
        public int GetHashCode((string AgentId, string SnapshotType) value) => HashCode.Combine(
            StringComparer.Ordinal.GetHashCode(value.AgentId), StringComparer.Ordinal.GetHashCode(value.SnapshotType));
    }
}
