using System.Globalization;
using System.Text;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Passive;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxProcfsProcessSourceTests
{
    private const string ProcRoot = "/synthetic-proc";
    private const string BootId = "11111111-2222-4333-8444-555555555555";

    [Fact]
    public async Task DisappearingAndReusedEntriesAreExpectedRacesNotCoverageGaps()
    {
        var procfs = Procfs(100, 101, 102);
        procfs.AddText(Path(100, "stat"), Stat(100, 1, 5000));
        procfs.AddResult(Path(101, "stat"), Missing());
        procfs.AddResults(
            Path(102, "stat"),
            Text(Stat(102, 1, 6000)),
            Text(Stat(102, 1, 6001)));
        var source = new LinuxProcfsProcessSource(ProcRoot, procfs);

        var read = await source.ReadAsync(new PassiveTelemetryOptions(), default);

        Assert.Equal(PassiveReadStatuses.Success, read.Status);
        Assert.Equal("none", read.ErrorCode);
        Assert.Single(read.Items);
        Assert.Equal(2, read.SkippedCount);
        Assert.Equal(2, read.ExpectedRaceSkipCount);
        Assert.Equal(0, read.CoverageGapReadSkipCount);
        Assert.Equal(0, read.VisibilityGapCount);
        Assert.Equal("2", read.Details!["expected_race_skips"]);
        Assert.Equal("0", read.Details["coverage_gap_read_skips"]);
    }

    [Fact]
    public async Task AllDisappearingOrReusedEntriesRemainASuccessfulEmptyObservation()
    {
        var procfs = Procfs(110, 111);
        procfs.AddResult(Path(110, "stat"), Missing());
        procfs.AddResults(
            Path(111, "stat"),
            Text(Stat(111, 1, 6100)),
            Text(Stat(111, 1, 6101)));
        var source = new LinuxProcfsProcessSource(ProcRoot, procfs);

        var read = await source.ReadAsync(new PassiveTelemetryOptions(), default);

        Assert.Empty(read.Items);
        Assert.Equal(PassiveReadStatuses.Success, read.Status);
        Assert.Equal("none", read.ErrorCode);
        Assert.Equal(2, read.SkippedCount);
        Assert.Equal(2, read.ExpectedRaceSkipCount);
        Assert.Equal(0, read.CoverageGapReadSkipCount);
        Assert.Equal(0, read.VisibilityGapCount);
        Assert.Equal("2", read.Details!["expected_race_skips"]);
        Assert.Equal("0", read.Details["coverage_gap_read_skips"]);
    }

    [Fact]
    public async Task EmptyPidEnumerationRemainsMissing()
    {
        var source = new LinuxProcfsProcessSource(ProcRoot, Procfs());

        var read = await source.ReadAsync(new PassiveTelemetryOptions(), default);

        Assert.Empty(read.Items);
        Assert.Equal(PassiveReadStatuses.Missing, read.Status);
        Assert.Equal("no_readable_processes", read.ErrorCode);
        Assert.Equal(0, read.SkippedCount);
        Assert.Equal(0, read.ExpectedRaceSkipCount);
        Assert.Equal(0, read.CoverageGapReadSkipCount);
        Assert.Equal(0, read.VisibilityGapCount);
    }

    [Fact]
    public async Task DeniedMetadataKeepsIdentityButDegradesEnrichmentExplicitly()
    {
        var procfs = Procfs(200);
        procfs.AddText(Path(200, "stat"), Stat(200, 1, 7000));
        procfs.AddResult(Path(200, "status"), new(null, "permission_denied", false));
        var source = new LinuxProcfsProcessSource(ProcRoot, procfs);

        var read = await source.ReadAsync(new PassiveTelemetryOptions(), default);

        var observation = Assert.Single(read.Items);
        Assert.True(observation.EnrichmentPartial);
        Assert.Equal(PassiveReadStatuses.Partial, read.Status);
        Assert.Equal("process_metadata_permission_denied", read.ErrorCode);
        Assert.Equal(0, read.SkippedCount);
        Assert.Equal(0, read.ExpectedRaceSkipCount);
        Assert.Equal(0, read.CoverageGapReadSkipCount);
        Assert.Equal(1, read.VisibilityGapCount);
        Assert.Equal("1", read.Details!["permission_denied_reads"]);
    }

    [Fact]
    public async Task IoErrorInCoreMetadataRemainsACoverageGap()
    {
        var procfs = Procfs(250);
        procfs.AddText(Path(250, "stat"), Stat(250, 1, 7500));
        procfs.AddResult(Path(250, "status"), new(null, "io_error", false));
        var source = new LinuxProcfsProcessSource(ProcRoot, procfs);

        var read = await source.ReadAsync(new PassiveTelemetryOptions(), default);

        Assert.True(Assert.Single(read.Items).EnrichmentPartial);
        Assert.Equal(PassiveReadStatuses.Partial, read.Status);
        Assert.Equal("process_metadata_unreadable", read.ErrorCode);
        Assert.Equal(1, read.VisibilityGapCount);
        Assert.Equal("0", read.Details!["malformed_metadata_records"]);
        Assert.Contains("status_io_error=1", read.Details["process_failure_classes"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task MalformedStatAndStatusAreCoverageGapsRatherThanRaces()
    {
        var procfs = Procfs(300, 301);
        procfs.AddText(Path(300, "stat"), Stat(300, 1, 8000));
        procfs.AddText(Path(300, "status"), "Uid:\tnot-a-number\nSeccomp:\tbroken\n");
        procfs.AddText(Path(301, "stat"), "301 malformed-stat");
        var source = new LinuxProcfsProcessSource(ProcRoot, procfs);

        var read = await source.ReadAsync(new PassiveTelemetryOptions(), default);

        Assert.True(Assert.Single(read.Items).EnrichmentPartial);
        Assert.Equal(PassiveReadStatuses.Partial, read.Status);
        Assert.Equal("process_metadata_malformed", read.ErrorCode);
        Assert.Equal(1, read.SkippedCount);
        Assert.Equal(0, read.ExpectedRaceSkipCount);
        Assert.Equal(1, read.CoverageGapReadSkipCount);
        Assert.Equal(2, read.VisibilityGapCount);
        Assert.Equal("2", read.Details!["malformed_metadata_records"]);
        Assert.Contains("stat_invalid=1", read.Details["process_failure_classes"], StringComparison.Ordinal);
        Assert.Contains("status_invalid=1", read.Details["process_failure_classes"], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("invalid_utf8", false, "command_line_invalid_utf8")]
    [InlineData("field_truncated", true, "command_line_truncated")]
    public async Task OneOptionalCommandLineOmissionUsesAggregateVisibility(
        string errorCode,
        bool truncated,
        string expectedFailureClass)
    {
        var processIds = Enumerable.Range(400, 10).ToArray();
        var procfs = Procfs(processIds);
        foreach (var processId in processIds)
        {
            procfs.AddText(Path(processId, "stat"), Stat(processId, 1, 9000 + processId));
            procfs.AddLink(Path(processId, "exe"), new("/usr/bin/synthetic", "none"));
            procfs.AddText(Path(processId, "cmdline"), "/usr/bin/synthetic\0--safe\0");
        }
        procfs.AddResult(
            Path(processIds[0], "cmdline"),
            truncated
                ? new("/usr/bin/synthetic", errorCode, true)
                : new(null, errorCode, false));
        var source = new LinuxProcfsProcessSource(ProcRoot, procfs);

        var read = await source.ReadAsync(new PassiveTelemetryOptions(), default);

        Assert.Equal(PassiveReadStatuses.Success, read.Status);
        Assert.Equal("none", read.ErrorCode);
        Assert.Equal(0, read.VisibilityGapCount);
        Assert.Equal("900", read.Details!["command_line_readability_permille"]);
        Assert.Equal("1000", read.Details["executable_readability_permille"]);
        Assert.Equal("0", read.Details["malformed_metadata_records"]);
        Assert.Equal("1", read.Details["optional_enrichment_omissions"]);
        Assert.Contains($"{expectedFailureClass}=1", read.Details["process_failure_classes"], StringComparison.Ordinal);
        var omitted = Assert.Single(read.Items, item => item.ProcessId == processIds[0]);
        Assert.True(omitted.EnrichmentPartial);
        Assert.Null(omitted.CommandLine);
        Assert.True(omitted.CommandLineRedacted);
        Assert.Equal(truncated, omitted.CommandLineTruncated);
        Assert.Equal(!truncated, omitted.InvalidText);
    }

    [Fact]
    public async Task OneOptionalExecutableOmissionUsesAggregateVisibility()
    {
        var processIds = Enumerable.Range(500, 10).ToArray();
        var procfs = Procfs(processIds);
        foreach (var processId in processIds)
        {
            procfs.AddText(Path(processId, "stat"), Stat(processId, 1, 10000 + processId));
            procfs.AddText(Path(processId, "cmdline"), "/usr/bin/synthetic\0--safe\0");
            procfs.AddLink(Path(processId, "exe"), new("/usr/bin/synthetic", "none"));
        }
        procfs.AddLink(Path(processIds[0], "exe"), new(null, "field_truncated"));
        var source = new LinuxProcfsProcessSource(ProcRoot, procfs);

        var read = await source.ReadAsync(new PassiveTelemetryOptions(), default);

        Assert.Equal(PassiveReadStatuses.Success, read.Status);
        Assert.Equal("none", read.ErrorCode);
        Assert.Equal(0, read.VisibilityGapCount);
        Assert.Equal("1000", read.Details!["command_line_readability_permille"]);
        Assert.Equal("900", read.Details["executable_readability_permille"]);
        Assert.Equal("1", read.Details["optional_enrichment_omissions"]);
        Assert.Contains("executable_field_truncated=1", read.Details["process_failure_classes"], StringComparison.Ordinal);
        var omitted = Assert.Single(read.Items, item => item.ProcessId == processIds[0]);
        Assert.True(omitted.EnrichmentPartial);
        Assert.Null(omitted.Executable);
        Assert.True(omitted.ExecutableTruncated);
    }

    private static FakeLinuxProcessProcfs Procfs(params int[] processIds)
    {
        var procfs = new FakeLinuxProcessProcfs(ProcRoot, processIds);
        procfs.AddText(
            System.IO.Path.Combine(ProcRoot, "self", "mountinfo"),
            "24 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n");
        procfs.AddText(
            System.IO.Path.Combine(ProcRoot, "sys", "kernel", "random", "boot_id"),
            BootId + "\n");
        return procfs;
    }

    private static string Path(int processId, string field) =>
        System.IO.Path.Combine(ProcRoot, processId.ToString(CultureInfo.InvariantCulture), field);

    private static string Stat(int processId, int parentProcessId, long startTicks) =>
        $"{processId} (synthetic worker) S {parentProcessId} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {startTicks} 0 0";

    private static ProcfsTextResult Text(string value) => new(value, "none", false);
    private static ProcfsTextResult Missing() => new(null, "missing", false);

    private sealed class FakeLinuxProcessProcfs(string root, IReadOnlyCollection<int> processIds) : ILinuxProcessProcfs
    {
        private readonly IReadOnlyList<string> directories = processIds
            .Select(processId => System.IO.Path.Combine(root, processId.ToString(CultureInfo.InvariantCulture)))
            .ToArray();
        private readonly Dictionary<string, Queue<ProcfsTextResult>> reads = new(StringComparer.Ordinal);
        private readonly Dictionary<string, ProcfsLinkResult> links = new(StringComparer.Ordinal);

        public bool DirectoryExists(string path) => string.Equals(path, root, StringComparison.Ordinal);

        public IEnumerable<string> EnumerateDirectories(string path) => directories;

        public Task<ProcfsTextResult> ReadTextAsync(
            string path,
            int maximumBytes,
            ProcfsReadBudget budget,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!reads.TryGetValue(path, out var results) || results.Count == 0)
                return Task.FromResult(Missing());
            var result = results.Count == 1 ? results.Peek() : results.Dequeue();
            if (result.Text is not null)
                budget.Record(Math.Min(Encoding.UTF8.GetByteCount(result.Text), maximumBytes));
            return Task.FromResult(result);
        }

        public ProcfsLinkResult ReadLink(string path) =>
            links.GetValueOrDefault(path, new ProcfsLinkResult(null, "missing"));

        public void AddLink(string path, ProcfsLinkResult result) => links[path] = result;

        public void AddText(string path, string value) => AddResult(path, Text(value));

        public void AddResult(string path, ProcfsTextResult result) =>
            reads[path] = new Queue<ProcfsTextResult>([result]);

        public void AddResults(string path, params ProcfsTextResult[] results) =>
            reads[path] = new Queue<ProcfsTextResult>(results);
    }
}
