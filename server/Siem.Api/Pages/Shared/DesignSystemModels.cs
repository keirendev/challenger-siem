namespace Challenger.Siem.Api.Pages.Shared;

public sealed record BreadcrumbItem(string Label, string? Page = null, string? Url = null, bool IsCurrent = false);

public sealed record BreadcrumbsModel(IReadOnlyList<BreadcrumbItem> Items)
{
    public static BreadcrumbsModel Create(params BreadcrumbItem[] items) => new(items);
}

public sealed record NoticeModel(string Title, string Message, string State = "info", bool IsAlert = false);

public sealed record BadgeModel(string Text, string State = "neutral", string? AccessibleLabel = null);

public sealed record PaginationModel(
    string Label,
    int PageNumber,
    bool HasPreviousPage,
    bool HasNextPage,
    string PreviousUrl,
    string NextUrl,
    string Summary);

public sealed record PlannedStateModel(string Title, string Message, string State = "planned", string? RoleHint = null);

public sealed record TabItem(string Label, string Url, bool IsActive = false, bool IsDisabled = false, string? Description = null);

public sealed record TabsModel(string Label, IReadOnlyList<TabItem> Items);

public sealed record LifecycleStateModel(string State, string Title, string Message, string Tone = "neutral");

public sealed record LifecycleStatesModel(string Label, IReadOnlyList<LifecycleStateModel> States);
