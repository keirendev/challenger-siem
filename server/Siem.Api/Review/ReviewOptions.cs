namespace Challenger.Siem.Api.Review;

public sealed class ReviewOptions
{
    public const string SectionName = "Review";

    public int StaleAgentMinutes { get; init; } = 15;
    public int RecentEventHours { get; init; } = 24;
    public int DefaultEventLimit { get; init; } = 100;

    public TimeSpan StaleAgentAfter => TimeSpan.FromMinutes(Math.Clamp(StaleAgentMinutes, 1, 24 * 60));

    public TimeSpan RecentEventWindow => TimeSpan.FromHours(Math.Clamp(RecentEventHours, 1, 24 * 30));

    public int NormalizedDefaultEventLimit => Math.Clamp(DefaultEventLimit, 1, 500);
}
