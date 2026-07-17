using System.Globalization;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Inventory;

public static class LinuxInventoryParsers
{
    public const int MaxItemsPerSnapshot = 200;
    private const int MaxTokenLength = 96;

    public static (InventorySourceState State, IReadOnlyList<InventoryItem> Items, bool Truncated, string ErrorCode) Parse(
        LinuxInventoryOperation operation, InventorySourceResult source)
    {
        if (source.State != InventorySourceState.Success)
            return (source.State, Array.Empty<InventoryItem>(), source.Truncated, source.ErrorCode);
        if (operation == LinuxInventoryOperation.SecureBoot
            && source.Content?.Contains("EFI variables are not supported", StringComparison.OrdinalIgnoreCase) == true)
            return (InventorySourceState.NotApplicable, Array.Empty<InventoryItem>(), source.Truncated, "non_efi_host");

        IReadOnlyList<InventoryItem>? parsed = operation switch
        {
            LinuxInventoryOperation.OsReleaseEtc or LinuxInventoryOperation.OsReleaseUsrLib => ParseOsRelease(source.Content),
            LinuxInventoryOperation.Kernel => ParseKernel(source.Content),
            LinuxInventoryOperation.Users => ParseAccounts(source.Content, false),
            LinuxInventoryOperation.Groups => ParseAccounts(source.Content, true),
            LinuxInventoryOperation.Services => ParseServices(source.Content, "service"),
            LinuxInventoryOperation.Units => ParseServices(source.Content, "unit"),
            LinuxInventoryOperation.Timers => ParseTimers(source.Content),
            LinuxInventoryOperation.DpkgPackages or LinuxInventoryOperation.RpmPackages => ParsePackages(source.Content),
            LinuxInventoryOperation.PacmanPackages => ParsePacmanPackages(source.Content),
            LinuxInventoryOperation.AptUpdates => ParseAptUpdates(source.Content),
            LinuxInventoryOperation.DnfUpdates => ParseDnfUpdates(source.Content),
            LinuxInventoryOperation.PacmanUpdates => ParsePacmanUpdates(source.Content),
            LinuxInventoryOperation.Interfaces => ParseInterfaces(source.Content),
            LinuxInventoryOperation.Listeners => ParseListeners(source.Content),
            LinuxInventoryOperation.Mounts => ParseMounts(source.Content),
            LinuxInventoryOperation.Nftables => ParseNftables(source.Content),
            LinuxInventoryOperation.Firewalld => ParseFixedState(source.Content, "firewall", "firewalld", new[] { "running", "not running" }),
            LinuxInventoryOperation.Ufw => ParseUfw(source.Content),
            LinuxInventoryOperation.SshConfig => ParseSsh(source.Content),
            LinuxInventoryOperation.AppArmor => new[] { Item("mandatory_access_control", "apparmor", source.ExitCode == 1 ? "disabled" : "enabled") },
            LinuxInventoryOperation.Selinux => ParseFixedState(source.Content, "mandatory_access_control", "selinux", new[] { "enforcing", "permissive", "disabled" }),
            LinuxInventoryOperation.SecureBoot => ParseSecureBoot(source.Content),
            LinuxInventoryOperation.AgentConfig => ParseAgentFile("configuration", source, UnixFileMode.UserRead | UnixFileMode.UserWrite, ownerMustBeRoot: false, requireFingerprint: false),
            LinuxInventoryOperation.AgentExecutable => ParseAgentFile("executable", source, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute, ownerMustBeRoot: true, requireFingerprint: true),
            _ => null
        };
        if (parsed is null)
            return (InventorySourceState.Malformed, Array.Empty<InventoryItem>(), source.Truncated, "unsupported_parser");
        if (parsed.Count == 0 && operation is not LinuxInventoryOperation.DpkgPackages and not LinuxInventoryOperation.RpmPackages
            and not LinuxInventoryOperation.PacmanPackages and not LinuxInventoryOperation.AptUpdates
            and not LinuxInventoryOperation.DnfUpdates and not LinuxInventoryOperation.PacmanUpdates)
            return (InventorySourceState.Malformed, Array.Empty<InventoryItem>(), source.Truncated, "malformed_output");

        var ordered = parsed.OrderBy(x => x.Name, StringComparer.Ordinal).ThenBy(x => x.Identity, StringComparer.Ordinal).ToArray();
        var bounded = ordered.Take(MaxItemsPerSnapshot).ToArray();
        return (InventorySourceState.Success, bounded, source.Truncated || ordered.Length > bounded.Length, "none");
    }

    public static bool IsNonSystemd(InventorySourceResult source)
    {
        if (source.State != InventorySourceState.Success) return false;
        var value = source.Content?.Trim().ToLowerInvariant();
        return value is "offline" or "unknown" || value?.Contains("not been booted", StringComparison.Ordinal) == true;
    }

    private static IReadOnlyList<InventoryItem>? ParseOsRelease(string? content)
    {
        if (content is null) return null;
        var allowed = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ID"] = "distribution_id", ["VERSION_ID"] = "version_id", ["PRETTY_NAME"] = "distribution"
        };
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in Lines(content))
        {
            var separator = line.IndexOf('=');
            if (separator <= 0 || !allowed.TryGetValue(line[..separator], out var key)) continue;
            var value = line[(separator + 1)..].Trim().Trim('"');
            var safe = key == "distribution" ? SafeText(value, 96) : SafeToken(value);
            if (safe is not null) metadata[key] = safe;
        }
        return metadata.Count == 0 ? null : new[] { Item("operating_system", metadata.GetValueOrDefault("distribution_id", "linux"), "observed", metadata) };
    }

    private static IReadOnlyList<InventoryItem>? ParseKernel(string? content)
    {
        var text = SafeText(content?.Trim(), 160);
        return text is null ? null : new[] { Item("kernel", "linux_kernel", "observed", new Dictionary<string, string> { ["release"] = text }) };
    }

    private static IReadOnlyList<InventoryItem>? ParseAccounts(string? content, bool group)
    {
        if (content is null) return null;
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            var fields = line.Split(':');
            if (fields.Length < (group ? 3 : 4)) continue;
            var name = SafeToken(fields[0]);
            var id = SafeUnsigned(group ? fields[2] : fields[2]);
            if (name is null || id is null) continue;
            items.Add(Item(group ? "local_group" : "local_user", name, "present", new Dictionary<string, string> { [group ? "gid" : "uid"] = id }));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParseServices(string? content, string kind)
    {
        if (content is null) return null;
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            var fields = SplitFields(line.TrimStart('●', ' '));
            if (fields.Length < 4 || (kind == "service" && !fields[0].EndsWith(".service", StringComparison.Ordinal))) continue;
            var name = SafeUnit(fields[0]);
            var load = SafeEnum(fields[1], "loaded", "not-found", "masked");
            var active = SafeEnum(fields[2], "active", "inactive", "failed", "activating", "deactivating", "reloading");
            var sub = SafeToken(fields[3]);
            if (name is null || load is null || active is null || sub is null) continue;
            items.Add(Item(kind, name, active, new Dictionary<string, string> { ["load_state"] = load, ["sub_state"] = sub }));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParseTimers(string? content)
    {
        if (content is null) return null;
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            var fields = SplitFields(line);
            if (fields.Length < 2 || !fields[0].EndsWith(".timer", StringComparison.Ordinal)) continue;
            var name = SafeUnit(fields[0]);
            var state = SafeEnum(fields[1], "enabled", "enabled-runtime", "disabled", "static", "masked", "generated", "transient");
            if (name is not null && state is not null) items.Add(Item("timer", name, state));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParsePackages(string? content)
    {
        if (content is null) return null;
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            var fields = line.Split('\t');
            if (fields.Length != 2) continue;
            var name = SafeToken(fields[0]);
            var version = SafeToken(fields[1]);
            if (name is not null && version is not null)
                items.Add(Item("package", name, "installed", new Dictionary<string, string> { ["version"] = version }));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParsePacmanPackages(string? content)
    {
        if (content is null) return null;
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            var fields = SplitFields(line);
            if (fields.Length != 2) continue;
            var name = SafeToken(fields[0]);
            var version = SafeToken(fields[1]);
            if (name is not null && version is not null)
                items.Add(Item("package", name, "installed", new Dictionary<string, string> { ["version"] = version }));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParseAptUpdates(string? content)
    {
        if (content is null) return null;
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            if (line.StartsWith("Listing", StringComparison.Ordinal)) continue;
            var fields = SplitFields(line);
            if (fields.Length < 2) continue;
            var slash = fields[0].IndexOf('/');
            var name = SafeToken(slash > 0 ? fields[0][..slash] : fields[0]);
            var version = SafeToken(fields[1]);
            if (name is not null && version is not null)
                items.Add(Item("package_update", name, "available", new Dictionary<string, string> { ["version"] = version }));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParseDnfUpdates(string? content)
    {
        if (content is null) return null;
        var architectures = new HashSet<string>(StringComparer.Ordinal) { "x86_64", "noarch", "aarch64", "i686", "ppc64le", "s390x", "src" };
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            var fields = SplitFields(line);
            if (fields.Length < 3) continue;
            var separator = fields[0].LastIndexOf('.');
            if (separator <= 0 || !architectures.Contains(fields[0][(separator + 1)..])) continue;
            var name = SafeToken(fields[0][..separator]);
            var version = SafeToken(fields[1]);
            if (name is not null && version is not null)
                items.Add(Item("package_update", name, "available", new Dictionary<string, string> { ["version"] = version }));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParsePacmanUpdates(string? content)
    {
        if (content is null) return null;
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            var fields = SplitFields(line);
            if (fields.Length != 4 || fields[2] != "->") continue;
            var name = SafeToken(fields[0]);
            var version = SafeToken(fields[3]);
            if (name is not null && version is not null)
                items.Add(Item("package_update", name, "available", new Dictionary<string, string> { ["version"] = version }));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParseInterfaces(string? content)
    {
        if (content is null) return null;
        var items = new List<InventoryItem>();
        foreach (var line in Lines(content))
        {
            var firstColon = line.IndexOf(':');
            var secondColon = firstColon < 0 ? -1 : line.IndexOf(':', firstColon + 1);
            if (firstColon < 1 || secondColon < 0) continue;
            var rawName = line[(firstColon + 1)..secondColon].Trim().Split('@')[0];
            var name = SafeToken(rawName);
            var stateAt = line.IndexOf(" state ", StringComparison.Ordinal);
            var state = stateAt < 0 ? "unknown" : SafeEnum(SplitFields(line[(stateAt + 7)..]).FirstOrDefault(), "up", "down", "unknown", "dormant", "lowerlayerdown");
            if (name is not null && state is not null) items.Add(Item("network_interface", name, state));
        }
        return items;
    }

    private static IReadOnlyList<InventoryItem>? ParseListeners(string? content)
    {
        if (content is null) return null;
        var values = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in Lines(content))
        {
            var fields = SplitFields(line);
            if (fields.Length < 5) continue;
            var protocol = SafeEnum(fields[0], "tcp", "udp");
            var endpoint = fields[4];
            var colon = endpoint.LastIndexOf(':');
            var port = colon < 0 ? null : SafePort(endpoint[(colon + 1)..]);
            if (protocol is not null && port is not null) values.Add($"{protocol}:{port}");
        }
        return values.Select(value => Item("listening_socket", value, "listening")).ToArray();
    }

    private static IReadOnlyList<InventoryItem>? ParseMounts(string? content)
    {
        if (content is null) return null;
        return Lines(content).Select(SafeToken).Where(x => x is not null).GroupBy(x => x!, StringComparer.Ordinal)
            .Select(group => Item("mounted_filesystem", group.Key, "mounted", new Dictionary<string, string> { ["count"] = group.Count().ToString(CultureInfo.InvariantCulture) })).ToArray();
    }

    private static IReadOnlyList<InventoryItem>? ParseNftables(string? content)
    {
        if (content is null) return null;
        var count = Lines(content).Count(line => line.StartsWith("table ", StringComparison.Ordinal));
        return new[] { Item("firewall", "nftables", count > 0 ? "enabled" : "no_tables", new Dictionary<string, string> { ["table_count"] = count.ToString(CultureInfo.InvariantCulture) }) };
    }

    private static IReadOnlyList<InventoryItem>? ParseUfw(string? content)
    {
        if (content is null) return null;
        var first = Lines(content).FirstOrDefault();
        if (first is null || !first.StartsWith("Status:", StringComparison.Ordinal)) return null;
        var state = SafeEnum(first[7..].Trim(), "active", "inactive");
        return state is null ? null : new[] { Item("firewall", "ufw", state) };
    }

    private static IReadOnlyList<InventoryItem>? ParseSsh(string? content)
    {
        if (content is null) return null;
        var accepted = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["permitrootlogin"] = new(StringComparer.OrdinalIgnoreCase) { "yes", "no", "prohibit-password", "forced-commands-only" },
            ["passwordauthentication"] = new(StringComparer.OrdinalIgnoreCase) { "yes", "no" },
            ["pubkeyauthentication"] = new(StringComparer.OrdinalIgnoreCase) { "yes", "no" }
        };
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in Lines(content))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var fields = SplitFields(line);
            if (fields.Length < 2) continue;
            if (fields[0].Equals("Match", StringComparison.OrdinalIgnoreCase)) break;
            if (accepted.TryGetValue(fields[0], out var values) && values.Contains(fields[1]))
                metadata.TryAdd(fields[0].ToLowerInvariant(), fields[1].ToLowerInvariant());
        }
        return metadata.Count == 0 ? null : new[] { Item("ssh", "sshd", "observed_primary_config", metadata) };
    }

    private static IReadOnlyList<InventoryItem>? ParseSecureBoot(string? content)
    {
        var value = content?.Trim().ToLowerInvariant();
        var state = value switch { "secureboot enabled" => "enabled", "secureboot disabled" => "disabled", _ => null };
        return state is null ? null : new[] { Item("secure_boot", "uefi_secure_boot", state) };
    }

    private static IReadOnlyList<InventoryItem>? ParseAgentFile(string name, InventorySourceResult source, UnixFileMode expected, bool ownerMustBeRoot, bool requireFingerprint)
    {
        if (!source.FileMode.HasValue || !source.FileSize.HasValue || source.FileSize < 0 || !source.FileOwnerId.HasValue) return null;
        var actual = source.FileMode.Value;
        var expectedOwner = ownerMustBeRoot ? source.FileOwnerId == 0 : source.FileOwnerId != 0;
        var status = actual == expected && expectedOwner ? "expected_permissions" : "permission_drift";
        if (requireFingerprint && (source.Sha256 is null || source.Sha256.Length != 64 || !source.Sha256.All(char.IsAsciiHexDigit))) return null;
        var metadata = new Dictionary<string, string>
        {
            ["mode"] = Convert.ToString((int)actual, 8),
            ["owner_id"] = source.FileOwnerId.Value.ToString(CultureInfo.InvariantCulture),
            ["regular_file"] = "true"
        };
        if (source.Sha256 is not null) metadata["sha256"] = source.Sha256;
        return new[] { Item("agent_integrity", name, status, metadata) };
    }

    private static IReadOnlyList<InventoryItem>? ParseFixedState(string? content, string kind, string name, IReadOnlyList<string> accepted)
    {
        var value = content?.Trim().ToLowerInvariant();
        return value is not null && accepted.Contains(value, StringComparer.Ordinal)
            ? new[] { Item(kind, name, value.Replace(' ', '_')) }
            : null;
    }

    private static InventoryItem Item(string kind, string name, string status, IReadOnlyDictionary<string, string>? metadata = null) => new()
    {
        Kind = kind,
        Name = name,
        Status = status,
        Metadata = metadata ?? new Dictionary<string, string>()
    };

    private static IEnumerable<string> Lines(string content) => content.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n', StringSplitOptions.RemoveEmptyEntries);
    private static string[] SplitFields(string? value) => value?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? Array.Empty<string>();
    private static string? SafeUnsigned(string value) => uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) ? number.ToString(CultureInfo.InvariantCulture) : null;
    private static string? SafePort(string value) => ushort.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port > 0 ? port.ToString(CultureInfo.InvariantCulture) : null;
    private static string? SafeUnit(string value) => value.Length <= MaxTokenLength && value.All(IsTokenCharacter) ? value : null;
    private static string? SafeToken(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= MaxTokenLength && value.All(IsTokenCharacter) ? value : null;
    private static string? SafeEnum(string? value, params string[] accepted) => value is not null && accepted.Contains(value.ToLowerInvariant(), StringComparer.Ordinal) ? value.ToLowerInvariant() : null;
    private static string? SafeText(string? value, int max) => !string.IsNullOrWhiteSpace(value) && value.Length <= max && value.All(ch => IsTokenCharacter(ch) || ch == ' ' || ch == '(' || ch == ')') ? value : null;
    private static bool IsTokenCharacter(char ch) => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '_' or '@' or ':' or '+' or '/' or '-';
}
