using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Inventory;

public static class WindowsInventoryCollectors
{
    public static readonly IReadOnlyList<string> SnapshotTypes = new[]
    {
        "host_identity",
        "network",
        "local_users_groups",
        "services_drivers",
        "scheduled_tasks_autoruns",
        "installed_software",
        "patches_features",
        "defender_firewall_bitlocker_policy",
        "audit_policy",
        "windows_role_detection"
    };

    public static AssetInventorySnapshot CreateHostIdentitySnapshot(string agentId, string hostname)
    {
        return new AssetInventorySnapshot
        {
            AgentId = agentId,
            Hostname = hostname,
            SnapshotType = "host_identity",
            CollectedAt = DateTimeOffset.UtcNow,
            Items = new[]
            {
                new InventoryItem { Kind = "host", Name = hostname, Status = "observed", Metadata = new Dictionary<string, string> { ["os"] = Environment.OSVersion.VersionString } },
                new InventoryItem { Kind = "network", Name = "network_interfaces", Status = "not_collected_in_mvp", Metadata = new Dictionary<string, string> { ["collector"] = "design_ready" } }
            },
            Summary = new Dictionary<string, string> { ["coverage"] = "host identity and network snapshot collector skeleton" }
        };
    }

    public static AssetInventorySnapshot CreateAuditPolicySnapshot(string agentId, string hostname, IReadOnlyDictionary<string, string> policyState)
    {
        return new AssetInventorySnapshot
        {
            AgentId = agentId,
            Hostname = hostname,
            SnapshotType = "audit_policy",
            CollectedAt = DateTimeOffset.UtcNow,
            Items = policyState.Select(pair => new InventoryItem
            {
                Kind = "audit_policy_subcategory",
                Name = pair.Key,
                Status = pair.Value,
                Metadata = new Dictionary<string, string> { ["baseline"] = RequiredAuditPolicy.IsRequired(pair.Key) ? "required" : "informational" }
            }).ToArray(),
            Summary = new Dictionary<string, string>
            {
                ["required_enabled"] = policyState.Count(pair => RequiredAuditPolicy.IsRequired(pair.Key) && pair.Value.Contains("success", StringComparison.OrdinalIgnoreCase)).ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["drift_count"] = RequiredAuditPolicy.CountDrift(policyState).ToString(System.Globalization.CultureInfo.InvariantCulture)
            }
        };
    }

    public static AssetInventorySnapshot CreateSecurityControlSnapshot(
        string agentId,
        string hostname,
        string defenderStatus,
        string firewallStatus,
        string bitLockerStatus,
        string localPolicyStatus)
    {
        return new AssetInventorySnapshot
        {
            AgentId = agentId,
            Hostname = hostname,
            SnapshotType = "defender_firewall_bitlocker_policy",
            CollectedAt = DateTimeOffset.UtcNow,
            Items = new[]
            {
                new InventoryItem { Kind = "defender", Name = "Microsoft Defender", Status = defenderStatus },
                new InventoryItem { Kind = "firewall", Name = "Windows Firewall", Status = firewallStatus },
                new InventoryItem { Kind = "bitlocker", Name = "BitLocker", Status = bitLockerStatus },
                new InventoryItem { Kind = "local_policy", Name = "Local security policy", Status = localPolicyStatus }
            },
            Summary = new Dictionary<string, string>
            {
                ["defender"] = defenderStatus,
                ["firewall"] = firewallStatus,
                ["bitlocker"] = bitLockerStatus,
                ["local_policy"] = localPolicyStatus
            }
        };
    }
}

public static class RequiredAuditPolicy
{
    public static readonly IReadOnlyDictionary<string, string> RequiredSubcategories = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Logon"] = "Success and Failure",
        ["Logoff"] = "Success",
        ["Account Lockout"] = "Success and Failure",
        ["User Account Management"] = "Success and Failure",
        ["Security Group Management"] = "Success and Failure",
        ["Process Creation"] = "Success",
        ["Audit Policy Change"] = "Success and Failure",
        ["Security State Change"] = "Success and Failure",
        ["Other Object Access Events"] = "Success and Failure"
    };

    public static bool IsRequired(string subcategory) => RequiredSubcategories.ContainsKey(subcategory);

    public static bool ProcessCommandLineAuditRequired(IReadOnlyDictionary<string, string> registryValues)
    {
        return registryValues.TryGetValue("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled", out var value)
            && value == "1";
    }

    public static bool PowerShellLoggingRequired(IReadOnlyDictionary<string, string> policyValues)
    {
        return policyValues.TryGetValue("ScriptBlockLogging", out var scriptBlock) && scriptBlock == "1"
            && policyValues.TryGetValue("ModuleLogging", out var moduleLogging) && moduleLogging == "1"
            && policyValues.TryGetValue("Transcription", out var transcription) && transcription == "1";
    }

    public static int CountDrift(IReadOnlyDictionary<string, string> policyState)
    {
        return RequiredSubcategories.Count(required =>
            !policyState.TryGetValue(required.Key, out var actual)
            || !actual.Contains("success", StringComparison.OrdinalIgnoreCase));
    }
}

public static class WindowsRoleDetector
{
    public static IReadOnlyList<string> DetectRoles(IReadOnlyList<string> installedFeatures, IReadOnlyList<string> runningServices)
    {
        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddIf(roles, installedFeatures, runningServices, "domain_controller", "AD-Domain-Services", "NTDS");
        AddIf(roles, installedFeatures, runningServices, "file_server", "FS-FileServer", "LanmanServer");
        AddIf(roles, installedFeatures, runningServices, "iis_web_server", "Web-Server", "W3SVC");
        AddIf(roles, installedFeatures, runningServices, "dns_server", "DNS", "DNS");
        AddIf(roles, installedFeatures, runningServices, "dhcp_server", "DHCP", "DHCPServer");
        AddIf(roles, installedFeatures, runningServices, "certificate_authority", "ADCS-Cert-Authority", "CertSvc");
        AddIf(roles, installedFeatures, runningServices, "hyper_v", "Hyper-V", "vmms");
        AddIf(roles, installedFeatures, runningServices, "rds_session_host", "RDS-RD-Server", "TermService");
        AddIf(roles, installedFeatures, runningServices, "print_server", "Print-Server", "Spooler");
        AddIf(roles, installedFeatures, runningServices, "sql_server_host", "SQL", "MSSQLSERVER");
        AddIf(roles, installedFeatures, runningServices, "openssh_server", "OpenSSH.Server", "sshd");
        return roles.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void AddIf(HashSet<string> roles, IReadOnlyList<string> features, IReadOnlyList<string> services, string role, string feature, string service)
    {
        if (features.Any(item => item.Contains(feature, StringComparison.OrdinalIgnoreCase))
            || services.Any(item => item.Contains(service, StringComparison.OrdinalIgnoreCase)))
        {
            roles.Add(role);
        }
    }
}
