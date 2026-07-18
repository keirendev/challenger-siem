using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Inventory;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxL2JournalTests
{
    [Fact]
    public void CatalogDeclaresEverySecurityFamilyAndHonestRequirementMetadata()
    {
        var expectedIds = new[]
        {
            LinuxTelemetrySourceIds.LoginSession,
            LinuxTelemetrySourceIds.Ssh,
            LinuxTelemetrySourceIds.Privilege,
            LinuxTelemetrySourceIds.Scheduler,
            LinuxTelemetrySourceIds.PackageManagement,
            LinuxTelemetrySourceIds.Firewall,
            LinuxTelemetrySourceIds.KernelSecurity,
            LinuxTelemetrySourceIds.ServiceChange,
            LinuxTelemetrySourceIds.AgentLogTamper
        };

        Assert.Equal(expectedIds.Order(StringComparer.Ordinal), LinuxTelemetrySourceCatalog.L2Security.Select(item => item.SourceId).Order(StringComparer.Ordinal));
        Assert.All(LinuxTelemetrySourceCatalog.L2Security, entry =>
        {
            Assert.Equal(TelemetryPlatforms.Linux, entry.Platform);
            Assert.Equal(TelemetrySourceKinds.LinuxJournal, entry.SourceKind);
            Assert.Equal(WindowsCoverageLevel.L2, entry.CoverageLevel);
            Assert.Equal(LinuxTelemetrySourceCatalog.L2PackId, entry.SourcePack);
            Assert.False(entry.EnabledByDefault);
            Assert.NotEmpty(entry.Prerequisites);
            Assert.NotEmpty(entry.EventFamilies);
            Assert.NotEmpty(entry.ValidationScenarios);
            Assert.Contains(entry.Requirement!, SourceRequirementKinds.All);
            Assert.Equal(entry.Requirement == SourceRequirementKinds.Mandatory, entry.Required);
        });

        var ssh = Assert.Single(LinuxTelemetrySourceCatalog.L2Security, item => item.SourceId == LinuxTelemetrySourceIds.Ssh);
        Assert.Equal(SourceRequirementKinds.RoleSpecific, ssh.Requirement);
        Assert.Equal(new[] { "ssh_server", "bastion" }, ssh.ApplicableRoles);
        var firewall = Assert.Single(LinuxTelemetrySourceCatalog.L2Security, item => item.SourceId == LinuxTelemetrySourceIds.Firewall);
        Assert.Equal(SourceRequirementKinds.Optional, firewall.Requirement);
        Assert.Equal(SourceApplicabilityStatuses.Unknown, firewall.Applicability);
        Assert.Equal(
            new[]
            {
                LinuxTelemetrySourceIds.AgentLogTamper,
                LinuxTelemetrySourceIds.KernelSecurity,
                LinuxTelemetrySourceIds.LoginSession
            }.Order(StringComparer.Ordinal),
            LinuxTelemetrySourceCatalog.SuccessfulJournalObservationSourceIds.Order(StringComparer.Ordinal));
        Assert.Equal(SourceApplicabilityStatuses.Unsupported, LinuxTelemetrySourceCatalog.UnsupportedAuditFramework.Applicability);
        Assert.Equal(TelemetrySourceKinds.LinuxAudit, LinuxTelemetrySourceCatalog.UnsupportedAuditFramework.SourceKind);

        var unknown = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
            WindowsCoverageLevel.L2,
            Array.Empty<string>(),
            new HashSet<string>(StringComparer.Ordinal));
        Assert.Equal(SourceApplicabilityStatuses.Unknown, Assert.Single(unknown, item => item.SourceId == LinuxTelemetrySourceIds.Ssh).Applicability);
        var declared = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
            WindowsCoverageLevel.L2,
            ["ssh_server"],
            new HashSet<string>(StringComparer.Ordinal));
        Assert.Equal(SourceApplicabilityStatuses.Applicable, Assert.Single(declared, item => item.SourceId == LinuxTelemetrySourceIds.Ssh).Applicability);
        var unrelated = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
            WindowsCoverageLevel.L2,
            ["general_server"],
            new HashSet<string>(StringComparer.Ordinal));
        Assert.Equal(SourceApplicabilityStatuses.NotApplicable, Assert.Single(unrelated, item => item.SourceId == LinuxTelemetrySourceIds.Ssh).Applicability);
        var observed = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
            WindowsCoverageLevel.L2,
            Array.Empty<string>(),
            new HashSet<string>(StringComparer.Ordinal) { LinuxTelemetrySourceIds.Ssh, LinuxTelemetrySourceIds.Firewall });
        Assert.Equal(SourceApplicabilityStatuses.Applicable, Assert.Single(observed, item => item.SourceId == LinuxTelemetrySourceIds.Ssh).Applicability);
        Assert.Equal(SourceApplicabilityStatuses.Applicable, Assert.Single(observed, item => item.SourceId == LinuxTelemetrySourceIds.Firewall).Applicability);
    }

    [Fact]
    public void JournalConfigurationDefaultsToL1AndBoundsL2Roles()
    {
        var options = TestOptions(WindowsCoverageLevel.L1);
        Assert.False(options.Journal.IncludeAccessibleUserJournals);
        Assert.True(options.HasValidJournalBounds());
        options.Journal.IncludeAccessibleUserJournals = true;
        Assert.True(options.HasValidJournalBounds());
        options.Journal.TargetCoverageLevel = WindowsCoverageLevel.L2;
        options.Journal.DeclaredRoles = ["ssh_server", "bastion"];
        Assert.True(options.HasValidJournalBounds());
        options.Journal.TargetCoverageLevel = WindowsCoverageLevel.L3;
        Assert.True(options.HasValidJournalBounds());
        options.Journal.TargetCoverageLevel = WindowsCoverageLevel.L4;
        Assert.True(options.HasValidJournalBounds());
        options.Journal.DeclaredRoles = [];
        Assert.False(options.HasValidJournalBounds());
        options.Journal.TargetCoverageLevel = WindowsCoverageLevel.L2;
        options.Journal.DeclaredRoles = ["invalid role"];
        Assert.False(options.HasValidJournalBounds());
        options.Journal.DeclaredRoles = ["SSH_SERVER"];
        Assert.False(options.HasValidJournalBounds());
        options.Journal.DeclaredRoles = ["ssh_server", "ssh_server"];
        Assert.False(options.HasValidJournalBounds());
    }

    [Fact]
    public void EveryL2FamilyHasPositiveAndNegativeSyntheticNormalizationCoverage()
    {
        var normalizer = new LinuxJournalNormalizer();
        var options = TestOptions(WindowsCoverageLevel.L2);
        var fixtures = FixtureCases();
        var catalogFamilies = LinuxTelemetrySourceCatalog.L2Security
            .SelectMany(entry => entry.EventFamilies)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(catalogFamilies, fixtures.Select(item => item.GetProperty("family").GetString()!).Order(StringComparer.Ordinal));
        Assert.Equal(catalogFamilies.Length, catalogFamilies.Distinct(StringComparer.Ordinal).Count());

        foreach (var fixture in fixtures)
        {
            var positiveJson = fixture.GetProperty("positive").GetRawText();
            Assert.True(normalizer.TryNormalize(positiveJson, options, DateTimeOffset.Parse("2026-07-13T12:00:00Z"), out var positive, out var positiveError),
                $"{fixture.GetProperty("family").GetString()} positive failed: {positiveError}");
            Assert.NotNull(positive);
            Assert.Equal(fixture.GetProperty("expected_source").GetString(), positive.Envelope.SourceId);
            Assert.Equal(fixture.GetProperty("family").GetString(), positive.EventFamily);
            Assert.Equal(fixture.GetProperty("expected_category").GetString(), positive.Envelope.Normalized?.Category);
            Assert.Equal(fixture.GetProperty("expected_action").GetString(), positive.Envelope.Normalized?.Action);
            Assert.Equal(fixture.GetProperty("expected_outcome").GetString(), positive.Envelope.Normalized?.Outcome);
            Assert.Equal(fixture.GetProperty("expected_severity").GetString(), positive.Envelope.Severity);
            Assert.Equal(positive.Envelope.EventId, DeterministicEventIdentity.ComputeSha256Uuid(positive.Envelope));
            Assert.InRange(positive.Envelope.DataHandling!.RawSizeBytes, 1, 4095);

            var negativeJson = fixture.GetProperty("negative").GetRawText();
            Assert.True(normalizer.TryNormalize(negativeJson, options, DateTimeOffset.Parse("2026-07-13T12:00:00Z"), out var negative, out var negativeError),
                $"{fixture.GetProperty("family").GetString()} negative failed: {negativeError}");
            Assert.NotNull(negative);
            Assert.Equal(LinuxTelemetrySourceIds.JournalL1, negative.Envelope.SourceId);
            Assert.Null(negative.Envelope.Normalized?.Action);
            Assert.Null(negative.Envelope.Normalized?.Outcome);
        }

        var ssh = NormalizeFixture(fixtures, "ssh_authentication", normalizer, options);
        Assert.Equal("synthetic-structured-user", ssh.Envelope.Normalized?.TargetUserName);
        Assert.Equal("192.0.2.10", ssh.Envelope.Normalized?.SourceIp);
        Assert.Equal("4242", ssh.Envelope.Normalized?.SourcePort);
        Assert.Equal("success", ssh.Envelope.Normalized?.Outcome);
        Assert.Equal("audit_success", ssh.Envelope.Severity);
        Assert.Equal("structured", ssh.Envelope.Normalized?.Labels["linux.evidence"]);

        var sudo = NormalizeFixture(fixtures, "sudo", normalizer, options);
        Assert.Equal("synthetic-user", sudo.Envelope.Normalized?.UserName);
        Assert.Equal("root", sudo.Envelope.Normalized?.TargetUserName);
        Assert.Equal("/usr/bin/sudo", sudo.Envelope.Normalized?.ProcessImage);
        Assert.Equal("/usr/bin/id --synthetic", sudo.Envelope.Normalized?.Process?.CommandLine);

        var package = NormalizeFixture(fixtures, "package_install", normalizer, options);
        Assert.Equal("synthetic-package", package.Envelope.Normalized?.PackageName);
        var firewall = NormalizeFixture(fixtures, "firewall_deny", normalizer, options);
        Assert.Equal("192.0.2.20", firewall.Envelope.Normalized?.Network?.SourceIp);
        Assert.Equal(12345, firewall.Envelope.Normalized?.Network?.SourcePort);
        Assert.Equal("198.51.100.20", firewall.Envelope.Normalized?.Network?.DestinationIp);
        Assert.Equal(22, firewall.Envelope.Normalized?.Network?.DestinationPort);
        Assert.Equal("tcp", firewall.Envelope.Normalized?.Network?.Protocol);
        Assert.Equal("tcp", firewall.Envelope.Normalized?.Protocol);

        var structuredFirewall = NormalizeFixture(fixtures, "firewall_allow", normalizer, options);
        Assert.Equal("192.0.2.40", structuredFirewall.Envelope.Normalized?.SourceIp);
        Assert.Equal("198.51.100.40", structuredFirewall.Envelope.Normalized?.DestinationIp);
        Assert.Equal("tcp", structuredFirewall.Envelope.Normalized?.Protocol);
        var serviceFailure = NormalizeFixture(fixtures, "service_failure", normalizer, options);
        Assert.Equal("synthetic-failure.service", serviceFailure.Envelope.Normalized?.ServiceName);

        var l1Options = TestOptions(WindowsCoverageLevel.L1);
        foreach (var fixture in fixtures)
        {
            Assert.True(normalizer.TryNormalize(fixture.GetProperty("positive").GetRawText(), l1Options, DateTimeOffset.UtcNow, out var l1, out _));
            Assert.Equal(LinuxTelemetrySourceIds.JournalL1, l1!.Envelope.SourceId);
            Assert.Null(l1.Envelope.Normalized?.Action);
            Assert.Null(l1.Envelope.Normalized?.Outcome);
        }
    }

    [Fact]
    public void PacmanAlpmPackageChangesAreClassifiedWithoutTreatingPacmanCommandsAsEvents()
    {
        var normalizer = new LinuxJournalNormalizer();
        var options = TestOptions(WindowsCoverageLevel.L2);
        var positive = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["__CURSOR"] = "s=synthetic-pacman;i=1;b=fake",
            ["__REALTIME_TIMESTAMP"] = "1783944100000050",
            ["_BOOT_ID"] = "00000000000000000000000000000002",
            ["_TRANSPORT"] = "syslog",
            ["SYSLOG_IDENTIFIER"] = "pacman",
            ["PRIORITY"] = "6",
            ["MESSAGE"] = "[ALPM] upgraded synthetic-package (1.2.3-1 -> 1.2.4-1)"
        });
        Assert.True(normalizer.TryNormalize(positive, options, DateTimeOffset.Parse("2026-07-13T12:00:00Z"), out var normalized, out var error), error);
        Assert.NotNull(normalized);
        Assert.Equal(LinuxTelemetrySourceIds.PackageManagement, normalized.Envelope.SourceId);
        Assert.Equal("package_update", normalized.EventFamily);
        Assert.Equal("update", normalized.Envelope.Normalized?.Action);
        Assert.Equal("synthetic-package", normalized.Envelope.Normalized?.PackageName);

        var negative = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["__CURSOR"] = "s=synthetic-pacman;i=2;b=fake",
            ["__REALTIME_TIMESTAMP"] = "1783944100000051",
            ["_BOOT_ID"] = "00000000000000000000000000000002",
            ["_TRANSPORT"] = "syslog",
            ["SYSLOG_IDENTIFIER"] = "pacman",
            ["PRIORITY"] = "6",
            ["MESSAGE"] = "[PACMAN] Running a synthetic read-only package query"
        });
        Assert.True(normalizer.TryNormalize(negative, options, DateTimeOffset.Parse("2026-07-13T12:00:00Z"), out var ignored, out var negativeError), negativeError);
        Assert.NotNull(ignored);
        Assert.Equal(LinuxTelemetrySourceIds.JournalL1, ignored.Envelope.SourceId);
        Assert.Null(ignored.Envelope.Normalized?.Action);
    }

    [Fact]
    public void MalformedAmbiguousSecretAndOversizedInputsRemainBounded()
    {
        var normalizer = new LinuxJournalNormalizer();
        var options = TestOptions(WindowsCoverageLevel.L2);
        var edge = EdgeFixture();
        Assert.False(normalizer.TryNormalize(edge["malformed_record"]!.GetValue<string>(), options, DateTimeOffset.UtcNow, out _, out var malformed));
        Assert.Equal("journal_record_malformed", malformed);

        var ambiguousFixture = edge["ambiguous_bounded_message"]!.AsObject();
        var ambiguousRecord = JsonNode.Parse(ambiguousFixture["record"]!.ToJsonString())!.AsObject();
        var prefixCharacter = ambiguousFixture["prefix_character"]!.GetValue<string>()[0];
        ambiguousRecord["MESSAGE"] = new string(prefixCharacter, ambiguousFixture["prefix_length"]!.GetValue<int>())
            + ambiguousFixture["message_suffix"]!.GetValue<string>();
        Assert.True(normalizer.TryNormalize(ambiguousRecord.ToJsonString(), options, DateTimeOffset.UtcNow, out var ambiguous, out _));
        Assert.Equal(ambiguousFixture["expected_source"]!.GetValue<string>(), ambiguous!.Envelope.SourceId);
        Assert.Null(ambiguous.Envelope.Normalized?.SourceIp);
        Assert.Null(ambiguous.Envelope.Normalized?.UserName);

        var secret = Record(new Dictionary<string, object>
        {
            ["__CURSOR"] = "s=synthetic-l2;i=secret;b=fake",
            ["__REALTIME_TIMESTAMP"] = "1783944200000001",
            ["_BOOT_ID"] = "00000000000000000000000000000003",
            ["_TRANSPORT"] = "syslog",
            ["SYSLOG_IDENTIFIER"] = "sudo",
            ["ACTION"] = "execute",
            ["RESULT"] = "success",
            ["_CMDLINE"] = "/usr/bin/synthetic password=FAKE-CANARY",
            ["MESSAGE"] = "Synthetic structured command."
        });
        Assert.True(normalizer.TryNormalize(secret, options, DateTimeOffset.UtcNow, out var redacted, out _));
        Assert.Contains("<redacted>", redacted!.Envelope.Normalized?.ProcessCommandLine);
        Assert.Contains("raw._CMDLINE", redacted.Envelope.DataHandling!.RedactedFields);

        var tinyInputLimit = TestOptions(WindowsCoverageLevel.L2);
        tinyInputLimit.Journal.MaxInputRecordBytes = 4096;
        var oversized = Record(new Dictionary<string, object>
        {
            ["__CURSOR"] = "s=synthetic-l2;i=oversized;b=fake",
            ["__REALTIME_TIMESTAMP"] = "1783944200000002",
            ["_BOOT_ID"] = "00000000000000000000000000000003",
            ["_TRANSPORT"] = "journal",
            ["MESSAGE"] = new string('z', 5000)
        });
        Assert.False(normalizer.TryNormalize(oversized, tinyInputLimit, DateTimeOffset.UtcNow, out _, out var oversizedCode));
        Assert.Equal("journal_record_oversized", oversizedCode);
    }

    [Fact]
    public async Task RuntimeReportsConfiguredLevelApplicabilityEvidenceAndPermissionStates()
    {
        using var temporary = new TemporaryState();
        var options = TestOptions(WindowsCoverageLevel.L1);
        options.State.Path = temporary.Path;
        var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(temporary.Path), TimeProvider.System);
        await runtime.InitializeAsync("1.1.0-test", "synthetic-config", default);
        var l1Snapshot = runtime.Snapshot();
        Assert.Equal(
            LinuxTelemetrySourceCatalog.All.Count(item => item.SourceKind is TelemetrySourceKinds.LinuxJournal or TelemetrySourceKinds.LinuxAudit),
            l1Snapshot.Manifest.Count);
        Assert.All(l1Snapshot.Health.Where(item => item.CoverageLevel == WindowsCoverageLevel.L2 && item.SourceId != LinuxTelemetrySourceIds.AuditFramework),
            item => Assert.Equal(SourceHealthStatuses.Disabled, item.Status));
        Assert.Equal(SourceHealthStatuses.Unsupported,
            Assert.Single(l1Snapshot.Health, item => item.SourceId == LinuxTelemetrySourceIds.AuditFramework).Status);

        options.Journal.TargetCoverageLevel = WindowsCoverageLevel.L2;
        options.Journal.DeclaredRoles = ["ssh_server"];
        var l2Runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(temporary.Path), TimeProvider.System);
        await l2Runtime.InitializeAsync("1.1.0-test", "synthetic-config", default);
        var sshFixture = FixtureCases().Single(item => item.GetProperty("family").GetString() == "ssh_authentication");
        Assert.True(new LinuxJournalNormalizer().TryNormalize(sshFixture.GetProperty("positive").GetRawText(), options, DateTimeOffset.UtcNow, out var ssh, out _));
        await l2Runtime.RecordCollectedAsync(ssh!, default);
        var l2Snapshot = l2Runtime.Snapshot();
        var sshManifest = Assert.Single(l2Snapshot.Manifest, item => item.SourceId == LinuxTelemetrySourceIds.Ssh);
        Assert.Equal(SourceApplicabilityStatuses.Applicable, sshManifest.Applicability);
        Assert.Equal(SourceRequirementKinds.RoleSpecific, sshManifest.Requirement);
        var sshHealth = Assert.Single(l2Snapshot.Health, item => item.SourceId == LinuxTelemetrySourceIds.Ssh);
        Assert.Equal(SourceHealthStatuses.Healthy, sshHealth.Status);
        Assert.Equal(SourceEvidenceStatuses.Observed, sshHealth.EventFamilyStatuses!["ssh_authentication"]);
        Assert.Equal(SourceEvidenceStatuses.Satisfied, sshHealth.PrerequisiteStatuses!["sshd_journal_visibility"]);
        Assert.Equal(sshHealth.Requirement, sshManifest.Requirement);

        l2Runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.PermissionDenied, Array.Empty<string>(), ErrorCode: "journal_permission_denied"));
        var denied = Assert.Single(l2Runtime.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.LoginSession);
        Assert.Equal(SourceHealthStatuses.PermissionDenied, denied.Status);
        Assert.All(denied.PrerequisiteStatuses!.Values, value => Assert.Equal(SourceEvidenceStatuses.PermissionDenied, value));

        options.Journal.DeclaredRoles = ["general_server"];
        using var unrelatedState = new TemporaryState();
        options.State.Path = unrelatedState.Path;
        var unrelatedRoleRuntime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(unrelatedState.Path), TimeProvider.System);
        await unrelatedRoleRuntime.InitializeAsync("1.1.0-test", "synthetic-config", default);
        var notApplicable = Assert.Single(unrelatedRoleRuntime.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.Ssh);
        Assert.Equal(SourceHealthStatuses.NotApplicable, notApplicable.Status);
        Assert.False(notApplicable.Enabled);
    }

    [Fact]
    public async Task RuntimeReportsNullLastEventTimeForUnobservedSources()
    {
        using var temporary = new TemporaryState();
        var options = TestOptions(WindowsCoverageLevel.L2);
        options.Journal.DeclaredRoles = ["ssh_server"];
        options.State.Path = temporary.Path;
        var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(temporary.Path), TimeProvider.System);
        await runtime.InitializeAsync("1.1.0-test", "synthetic-config", default);

        var ssh = Assert.Single(runtime.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.Ssh);

        Assert.Null(ssh.LastEventTime);
        Assert.Null(ssh.LagSeconds);
        Assert.Null(ssh.SilenceSeconds);
    }

    [Fact]
    public async Task PackageManagementInventoryAndJournalEvidenceStatesAreDeterministic()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory,
            "fixtures",
            "synthetic-linux-package-management-evidence-cases.json")));
        var packageFixtures = FixtureCases();
        var normalizer = new LinuxJournalNormalizer();

        foreach (var fixture in document.RootElement.EnumerateArray())
        {
            var expected = fixture.GetProperty("expected");
            var probes = fixture.GetProperty("probes").EnumerateArray()
                .Select(probe => new LinuxPackageManagerInventoryProbe(
                    probe.GetProperty("producer").GetString()!,
                    InventoryState(probe.GetProperty("state").GetString()!),
                    probe.GetProperty("error_code").GetString()!))
                .ToArray();
            var evidence = LinuxPackageManagementInventoryEvidence.Evaluate(
                fixture.GetProperty("distribution_id").GetString(),
                probes);
            Assert.Equal(expected.GetProperty("inventory_state").GetString(), evidence.State);
            Assert.Equal(expected.GetProperty("producer").GetString(), evidence.Producer);

            using var temporary = new TemporaryState();
            var options = TestOptions(WindowsCoverageLevel.L2);
            options.State.Path = temporary.Path;
            var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(temporary.Path), TimeProvider.System);
            await runtime.InitializeAsync("1.11.3-test", "synthetic-config", default);
            runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.Success, ["synthetic-journal-record"]));
            var summary = evidence.AddTo(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["state"] = "success",
                ["error_code"] = "none",
                ["item_count"] = "0",
                ["truncated"] = "false"
            });
            await runtime.ObserveInventoryAsync(
                [new AssetInventorySnapshot { SnapshotType = LinuxPackageManagementInventoryEvidence.SnapshotType, Summary = summary }],
                default);

            foreach (var family in fixture.GetProperty("observed_families").EnumerateArray().Select(item => item.GetString()!))
            {
                await runtime.RecordCollectedAsync(NormalizeFixture(packageFixtures, family, normalizer, options), default);
            }

            var health = Assert.Single(runtime.Snapshot().Health,
                item => item.SourceId == LinuxTelemetrySourceIds.PackageManagement);
            Assert.Equal(expected.GetProperty("applicability").GetString(), health.Applicability);
            Assert.Equal(expected.GetProperty("status").GetString(), health.Status);
            Assert.Equal(expected.GetProperty("error_code").GetString(), health.ErrorCode);
            Assert.Equal(expected.GetProperty("package_state").GetString(), health.Details!["package_management_state"]);
            Assert.Equal(expected.GetProperty("systemd_journal_readable").GetString(), health.PrerequisiteStatuses!["systemd_journal_readable"]);
            Assert.Equal(expected.GetProperty("package_manager_journal_visibility").GetString(), health.PrerequisiteStatuses["package_manager_journal_visibility"]);
            foreach (var family in new[] { "package_install", "package_update", "package_remove" })
            {
                Assert.Equal(expected.GetProperty(family).GetString(), health.EventFamilyStatuses![family]);
            }
        }
    }

    [Fact]
    public async Task RuntimeUsesSuccessfulJournalObservationForQuietTamperFamilies()
    {
        using var temporary = new TemporaryState();
        var now = DateTimeOffset.Parse("2026-07-18T12:00:00Z");
        var clock = new FixedTimeProvider(now);
        var options = TestOptions(WindowsCoverageLevel.L2);
        options.State.Path = temporary.Path;
        var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(temporary.Path), clock);
        await runtime.InitializeAsync("1.11.2-test", "synthetic-config", default);

        var fixtures = FixtureCases();
        var normalizer = new LinuxJournalNormalizer();
        await runtime.RecordCollectedAsync(NormalizeFixture(fixtures, "session", normalizer, options), default);
        runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.Success, Array.Empty<string>()));
        await runtime.RecordSuccessfulReadObservationAsync(default);

        var absent = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.AgentLogTamper);
        Assert.Equal(SourceHealthStatuses.Healthy, absent.Status);
        Assert.Equal(now, absent.ObservedAt);
        Assert.Null(absent.LastEventTime);
        Assert.All(absent.PrerequisiteStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.Satisfied, value));
        Assert.All(absent.EventFamilyStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.NotObserved, value));

        var oldAgentEvent = NormalizeFixture(fixtures, "agent_tamper", normalizer, options);
        await runtime.RecordCollectedAsync(oldAgentEvent, default);
        var old = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.AgentLogTamper);
        Assert.Equal(SourceHealthStatuses.Healthy, old.Status);
        Assert.Equal(now, old.ObservedAt);
        Assert.Equal(oldAgentEvent.Envelope.EventTime, old.LastEventTime);
        Assert.Equal(SourceEvidenceStatuses.Observed, old.EventFamilyStatuses!["agent_tamper"]);
        Assert.Equal(SourceEvidenceStatuses.NotObserved, old.EventFamilyStatuses["log_tamper"]);
    }

    [Fact]
    public async Task RuntimeUsesSuccessfulJournalObservationForQuietKernelSecurityFamilies()
    {
        using var temporary = new TemporaryState();
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var clock = new FixedTimeProvider(now);
        var options = TestOptions(WindowsCoverageLevel.L2);
        options.State.Path = temporary.Path;
        var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(temporary.Path), clock);
        await runtime.InitializeAsync("1.11.4-test", "synthetic-config", default);

        var fixtures = FixtureCases();
        var normalizer = new LinuxJournalNormalizer();
        await runtime.RecordCollectedAsync(NormalizeFixture(fixtures, "session", normalizer, options), default);
        runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.Success, Array.Empty<string>()));
        await runtime.RecordSuccessfulReadObservationAsync(default);

        var quiet = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.KernelSecurity);
        Assert.Equal(SourceApplicabilityStatuses.Applicable, quiet.Applicability);
        Assert.Equal(SourceHealthStatuses.Healthy, quiet.Status);
        Assert.Equal(now, quiet.ObservedAt);
        Assert.Null(quiet.LastEventTime);
        Assert.All(quiet.PrerequisiteStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.Satisfied, value));
        Assert.All(quiet.EventFamilyStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.NotObserved, value));
        Assert.Equal("successful_journal_read", quiet.Details!["freshness_basis"]);
        Assert.Equal("independent_observation_state", quiet.Details["event_family_freshness"]);

        var oldKernelModuleEvent = NormalizeFixture(fixtures, "kernel_module", normalizer, options);
        await runtime.RecordCollectedAsync(oldKernelModuleEvent, default);
        var partiallyObserved = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.KernelSecurity);
        Assert.Equal(SourceHealthStatuses.Healthy, partiallyObserved.Status);
        Assert.Equal(now, partiallyObserved.ObservedAt);
        Assert.Equal(oldKernelModuleEvent.Envelope.EventTime, partiallyObserved.LastEventTime);
        Assert.Equal(SourceEvidenceStatuses.Observed, partiallyObserved.EventFamilyStatuses!["kernel_module"]);
        Assert.Equal(SourceEvidenceStatuses.NotObserved, partiallyObserved.EventFamilyStatuses["kernel_security"]);
        Assert.Equal(SourceEvidenceStatuses.NotObserved, partiallyObserved.EventFamilyStatuses["security_module"]);

        runtime.RecordReadResult(new JournalReadResult(
            JournalReadStatus.Unavailable,
            Array.Empty<string>(),
            ErrorCode: "journal_unavailable"));
        var unavailable = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.KernelSecurity);
        Assert.Equal(SourceHealthStatuses.Missing, unavailable.Status);
        Assert.All(unavailable.PrerequisiteStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.Missing, value));

        runtime.RecordReadResult(new JournalReadResult(
            JournalReadStatus.PermissionDenied,
            Array.Empty<string>(),
            ErrorCode: "journal_permission_denied"));
        var denied = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.KernelSecurity);
        Assert.Equal(SourceHealthStatuses.PermissionDenied, denied.Status);
        Assert.All(denied.PrerequisiteStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.PermissionDenied, value));
    }

    [Fact]
    public async Task RuntimeUsesSuccessfulJournalObservationForQuietLoginSessionFamilies()
    {
        using var temporary = new TemporaryState();
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var clock = new FixedTimeProvider(now);
        var options = TestOptions(WindowsCoverageLevel.L2);
        options.State.Path = temporary.Path;
        var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(temporary.Path), clock);
        await runtime.InitializeAsync("1.11.5-test", "synthetic-config", default);

        var fixtures = FixtureCases();
        var normalizer = new LinuxJournalNormalizer();
        await runtime.RecordCollectedAsync(NormalizeFixture(fixtures, "kernel_module", normalizer, options), default);
        runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.Success, Array.Empty<string>()));
        await runtime.RecordSuccessfulReadObservationAsync(default);

        var quiet = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.LoginSession);
        Assert.Equal(SourceApplicabilityStatuses.Applicable, quiet.Applicability);
        Assert.Equal(SourceHealthStatuses.Healthy, quiet.Status);
        Assert.Equal(now, quiet.ObservedAt);
        Assert.Null(quiet.LastEventTime);
        Assert.All(quiet.PrerequisiteStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.Satisfied, value));
        Assert.All(quiet.EventFamilyStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.NotObserved, value));
        Assert.Equal("successful_journal_read", quiet.Details!["freshness_basis"]);
        Assert.Equal("independent_observation_state", quiet.Details["event_family_freshness"]);

        var loginEvent = NormalizeFixture(fixtures, "login", normalizer, options);
        await runtime.RecordCollectedAsync(loginEvent, default);
        var partiallyObserved = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.LoginSession);
        Assert.Equal(SourceHealthStatuses.Healthy, partiallyObserved.Status);
        Assert.Equal(now, partiallyObserved.ObservedAt);
        Assert.Equal(loginEvent.Envelope.EventTime, partiallyObserved.LastEventTime);
        Assert.Equal(SourceEvidenceStatuses.Observed, partiallyObserved.EventFamilyStatuses!["login"]);
        Assert.Equal(SourceEvidenceStatuses.NotObserved, partiallyObserved.EventFamilyStatuses["session"]);

        runtime.RecordReadResult(new JournalReadResult(
            JournalReadStatus.Unavailable,
            Array.Empty<string>(),
            ErrorCode: "journal_unavailable"));
        var unavailable = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.LoginSession);
        Assert.Equal(SourceHealthStatuses.Missing, unavailable.Status);
        Assert.All(unavailable.PrerequisiteStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.Missing, value));

        runtime.RecordReadResult(new JournalReadResult(
            JournalReadStatus.PermissionDenied,
            Array.Empty<string>(),
            ErrorCode: "journal_permission_denied"));
        var denied = Assert.Single(runtime.Snapshot().Health,
            item => item.SourceId == LinuxTelemetrySourceIds.LoginSession);
        Assert.Equal(SourceHealthStatuses.PermissionDenied, denied.Status);
        Assert.All(denied.PrerequisiteStatuses!.Values,
            value => Assert.Equal(SourceEvidenceStatuses.PermissionDenied, value));
    }

    [Fact]
    public void RepresentativeL2NormalizationBenchmarkIsBounded()
    {
        var fixtures = FixtureCases().Select(item => item.GetProperty("positive").GetRawText()).ToArray();
        var normalizer = new LinuxJournalNormalizer();
        var options = TestOptions(WindowsCoverageLevel.L2);
        const int count = 5000;
        var beforeMemory = GC.GetTotalAllocatedBytes(true);
        var stopwatch = Stopwatch.StartNew();
        for (var index = 0; index < count; index++)
        {
            Assert.True(normalizer.TryNormalize(fixtures[index % fixtures.Length], options, DateTimeOffset.UtcNow, out var record, out _));
            Assert.InRange(record!.Envelope.DataHandling!.RawSizeBytes, 1, 4095);
        }
        stopwatch.Stop();
        var allocated = GC.GetTotalAllocatedBytes(true) - beforeMemory;
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), $"L2 synthetic normalization took {stopwatch.Elapsed}.");
        Assert.True(allocated < 250L * 1024 * 1024, $"L2 synthetic normalization allocated {allocated} bytes.");
        Assert.True(count / stopwatch.Elapsed.TotalSeconds >= 500, "L2 synthetic normalization throughput fell below 500 records/s.");
    }

    private static NormalizedJournalRecord NormalizeFixture(
        IReadOnlyList<JsonElement> fixtures,
        string family,
        LinuxJournalNormalizer normalizer,
        LinuxAgentOptions options)
    {
        var fixture = fixtures.Single(item => item.GetProperty("family").GetString() == family);
        Assert.True(normalizer.TryNormalize(fixture.GetProperty("positive").GetRawText(), options, DateTimeOffset.UtcNow, out var normalized, out _));
        return normalized!;
    }

    private static IReadOnlyList<JsonElement> FixtureCases()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "synthetic-linux-l2-journal-cases.json")));
        return document.RootElement.EnumerateArray().Select(item => item.Clone()).ToArray();
    }

    private static JsonObject EdgeFixture() => JsonNode.Parse(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "synthetic-linux-l2-journal-edge-cases.json")))!.AsObject();

    private static LinuxAgentOptions TestOptions(WindowsCoverageLevel level) => new()
    {
        AgentId = "linux-synthetic-l2-001",
        ApiToken = "fake-test-token",
        ServerBaseUrl = new Uri("https://siem.synthetic"),
        Journal = new JournalOptions { TargetCoverageLevel = level },
        Queue = new QueueOptions { Path = "unused" },
        State = new StateOptions { Path = "unused" }
    };

    private static string Record(IReadOnlyDictionary<string, object> fields) => JsonSerializer.Serialize(fields);

    private static InventorySourceState InventoryState(string value) => value switch
    {
        "success" => InventorySourceState.Success,
        "unavailable" => InventorySourceState.Unavailable,
        "not_applicable" => InventorySourceState.NotApplicable,
        "permission_denied" => InventorySourceState.PermissionDenied,
        "timeout" => InventorySourceState.Timeout,
        "malformed" => InventorySourceState.Malformed,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unsupported synthetic inventory state.")
    };

    private sealed class TemporaryState : IDisposable
    {
        private readonly string root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "challenger-linux-l2-test-" + Guid.NewGuid().ToString("N"));
        public TemporaryState() => Directory.CreateDirectory(root);
        public string Path => System.IO.Path.Combine(root, "state.json");
        public void Dispose() => Directory.Delete(root, true);
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }
}
