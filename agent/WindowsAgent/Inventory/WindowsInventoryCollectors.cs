using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using Challenger.Siem.Contracts.V1;
using Microsoft.Win32;

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

    public static IReadOnlyList<AssetInventorySnapshot> CollectAllSnapshots(string agentId, string hostname)
    {
        return new[]
        {
            CreateHostIdentitySnapshot(agentId, hostname),
            CreateNetworkSnapshot(agentId, hostname),
            CreateLocalUsersGroupsSnapshot(agentId, hostname),
            CreateServicesDriversSnapshot(agentId, hostname),
            CreateScheduledTasksAutorunsSnapshot(agentId, hostname),
            CreateInstalledSoftwareSnapshot(agentId, hostname),
            CreatePatchesFeaturesSnapshot(agentId, hostname),
            CreateSecurityControlSnapshot(agentId, hostname),
            CreateAuditPolicySnapshot(agentId, hostname, CollectAuditPolicyState()),
            CreateWindowsRoleDetectionSnapshot(agentId, hostname)
        };
    }

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
                new InventoryItem
                {
                    Kind = "host",
                    Name = hostname,
                    Status = "observed",
                    Metadata = new Dictionary<string, string>
                    {
                        ["os"] = Environment.OSVersion.VersionString,
                        ["processor_count"] = Environment.ProcessorCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        ["is_64_bit_os"] = Environment.Is64BitOperatingSystem ? "true" : "false"
                    }
                }
            },
            Summary = new Dictionary<string, string>
            {
                ["os"] = Environment.OSVersion.VersionString,
                ["collector"] = "agent_bounded_inventory"
            }
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
            Summary = policyState.Count == 0
                ? new Dictionary<string, string>
                {
                    ["required_enabled"] = "unknown",
                    ["drift_count"] = "unknown",
                    ["collector"] = "auditpol_unavailable"
                }
                : new Dictionary<string, string>
                {
                    ["required_enabled"] = policyState.Count(pair => RequiredAuditPolicy.IsRequired(pair.Key) && RequiredAuditPolicy.SubcategoryMeetsBaseline(pair.Key, pair.Value)).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["drift_count"] = RequiredAuditPolicy.CountDrift(policyState).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["collector"] = "auditpol"
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

    private static AssetInventorySnapshot CreateNetworkSnapshot(string agentId, string hostname)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();
        var active = interfaces.Count(item => item.OperationalStatus == OperationalStatus.Up && item.NetworkInterfaceType != NetworkInterfaceType.Loopback);
        return CountSnapshot(agentId, hostname, "network", new[]
        {
            CountItem("network_interface", "interfaces_total", interfaces.Length),
            CountItem("network_interface", "interfaces_up", active)
        }, new Dictionary<string, string>
        {
            ["interfaces_total"] = interfaces.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["interfaces_up"] = active.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["collector"] = "dotnet_network_interface_counts"
        });
    }

    private static AssetInventorySnapshot CreateLocalUsersGroupsSnapshot(string agentId, string hostname)
    {
        var users = RunPowerShellCount("Get-LocalUser -ErrorAction Stop");
        var groups = RunPowerShellCount("Get-LocalGroup -ErrorAction Stop");
        return CountSnapshot(agentId, hostname, "local_users_groups", new[]
        {
            CountItem("local_user", "local_users", users),
            CountItem("local_group", "local_groups", groups)
        }, CountSummary("local_users", users, "local_groups", groups, "powershell_localaccounts_counts"));
    }

    private static AssetInventorySnapshot CreateServicesDriversSnapshot(string agentId, string hostname)
    {
        var (services, drivers, serviceNames) = CountServicesAndDrivers();
        return CountSnapshot(agentId, hostname, "services_drivers", new[]
        {
            CountItem("service", "services", services),
            CountItem("driver", "drivers", drivers)
        }, new Dictionary<string, string>
        {
            ["services"] = services.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["drivers"] = drivers.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["running_service_names_for_role_detection"] = serviceNames.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["collector"] = "registry_services_counts"
        });
    }

    private static AssetInventorySnapshot CreateScheduledTasksAutorunsSnapshot(string agentId, string hostname)
    {
        var tasks = RunPowerShellCount("Get-ScheduledTask -ErrorAction Stop");
        var autoruns = CountAutorunValues();
        return CountSnapshot(agentId, hostname, "scheduled_tasks_autoruns", new[]
        {
            CountItem("scheduled_task", "scheduled_tasks", tasks),
            CountItem("autorun", "registry_run_values", autoruns)
        }, CountSummary("scheduled_tasks", tasks, "registry_run_values", autoruns, "powershell_scheduledtask_and_registry_counts"));
    }

    private static AssetInventorySnapshot CreateInstalledSoftwareSnapshot(string agentId, string hostname)
    {
        var count = CountInstalledSoftware();
        return CountSnapshot(agentId, hostname, "installed_software", new[] { CountItem("software", "installed_software_entries", count) }, new Dictionary<string, string>
        {
            ["installed_software_entries"] = count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["collector"] = "registry_uninstall_counts"
        });
    }

    private static AssetInventorySnapshot CreatePatchesFeaturesSnapshot(string agentId, string hostname)
    {
        var hotfixes = RunPowerShellCount("Get-HotFix -ErrorAction Stop");
        var optionalFeatures = RunPowerShellCount("Get-WindowsOptionalFeature -Online -ErrorAction Stop");
        return CountSnapshot(agentId, hostname, "patches_features", new[]
        {
            CountItem("hotfix", "hotfixes", hotfixes),
            CountItem("windows_feature", "optional_features", optionalFeatures)
        }, CountSummary("hotfixes", hotfixes, "optional_features", optionalFeatures, "powershell_patch_feature_counts"));
    }

    private static AssetInventorySnapshot CreateSecurityControlSnapshot(string agentId, string hostname)
    {
        var defender = RunPowerShellScalar("try { if ((Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled) { 'enabled' } else { 'disabled' } } catch { 'unavailable' }") ?? "unavailable";
        var firewall = RunPowerShellScalar("try { $p=Get-NetFirewallProfile -ErrorAction Stop; (($p | Where-Object Enabled).Count).ToString() + '/' + ($p.Count).ToString() + '_profiles_enabled' } catch { 'unavailable' }") ?? "unavailable";
        var bitLocker = RunPowerShellScalar("try { (Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus.ToString() } catch { 'unavailable' }") ?? "unavailable";
        var localPolicy = RequiredAuditPolicy.CountDrift(CollectAuditPolicyState()) == 0 ? "audit_policy_baseline_met" : "audit_policy_drift";
        return CreateSecurityControlSnapshot(agentId, hostname, defender, firewall, bitLocker, localPolicy);
    }

    private static AssetInventorySnapshot CreateWindowsRoleDetectionSnapshot(string agentId, string hostname)
    {
        var (_, _, serviceNames) = CountServicesAndDrivers();
        var roles = WindowsRoleDetector.DetectRoles(Array.Empty<string>(), serviceNames);
        return new AssetInventorySnapshot
        {
            AgentId = agentId,
            Hostname = hostname,
            SnapshotType = "windows_role_detection",
            CollectedAt = DateTimeOffset.UtcNow,
            Items = roles.Select(role => new InventoryItem { Kind = "windows_role", Name = role, Status = "detected" }).ToArray(),
            Summary = new Dictionary<string, string>
            {
                ["detected_roles"] = roles.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["collector"] = "service_name_role_detection"
            }
        };
    }

    private static IReadOnlyDictionary<string, string> CollectAuditPolicyState()
    {
        var auditpolPath = Path.Combine(Environment.SystemDirectory, "auditpol.exe");
        var output = RunCommand(auditpolPath, "/get /category:* /r", TimeSpan.FromSeconds(10));
        if (string.IsNullOrWhiteSpace(output) || !output.Contains("Machine Name", StringComparison.OrdinalIgnoreCase))
        {
            var commandProcessor = Environment.GetEnvironmentVariable("ComSpec") ?? Path.Combine(Environment.SystemDirectory, "cmd.exe");
            output = RunCommand(commandProcessor, $"/c \"\"{auditpolPath}\" /get /category:* /r\"", TimeSpan.FromSeconds(10));
        }

        if (string.IsNullOrWhiteSpace(output))
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        var state = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Skip(1))
        {
            var columns = line.Split(',');
            if (columns.Length < 5)
            {
                continue;
            }

            var subcategory = columns[2].Trim().Trim('"');
            var inclusion = columns[4].Trim().Trim('"');
            if (!string.IsNullOrWhiteSpace(subcategory))
            {
                state[subcategory] = string.IsNullOrWhiteSpace(inclusion) ? "No Auditing" : inclusion;
            }
        }

        if (state.Count == 0)
        {
            foreach (var subcategory in RequiredAuditPolicy.RequiredSubcategories.Keys)
            {
                var setting = CollectAuditPolicySubcategory(auditpolPath, subcategory);
                if (!string.IsNullOrWhiteSpace(setting))
                {
                    state[subcategory] = setting;
                }
            }
        }

        return state;
    }

    private static string? CollectAuditPolicySubcategory(string auditpolPath, string subcategory)
    {
        var output = RunCommand(auditpolPath, $"/get /subcategory:\"{subcategory}\"", TimeSpan.FromSeconds(5));
        if (string.IsNullOrWhiteSpace(output))
        {
            return null;
        }

        foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith(subcategory, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var parts = System.Text.RegularExpressions.Regex.Split(trimmed, @"\s{2,}");
            if (parts.Length >= 2)
            {
                return parts[^1].Trim();
            }
        }

        return null;
    }

    private static AssetInventorySnapshot CountSnapshot(
        string agentId,
        string hostname,
        string snapshotType,
        IReadOnlyList<InventoryItem> items,
        IReadOnlyDictionary<string, string> summary) => new()
        {
            AgentId = agentId,
            Hostname = hostname,
            SnapshotType = snapshotType,
            CollectedAt = DateTimeOffset.UtcNow,
            Items = items,
            Summary = summary
        };

    private static InventoryItem CountItem(string kind, string name, int count) => new()
    {
        Kind = kind,
        Name = name,
        Status = count >= 0 ? "collected" : "unavailable",
        Metadata = new Dictionary<string, string>
        {
            ["count"] = count >= 0 ? count.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unknown"
        }
    };

    private static Dictionary<string, string> CountSummary(string firstName, int firstCount, string secondName, int secondCount, string collector) => new(StringComparer.OrdinalIgnoreCase)
    {
        [firstName] = firstCount >= 0 ? firstCount.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unknown",
        [secondName] = secondCount >= 0 ? secondCount.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unknown",
        ["collector"] = collector
    };

    private static int RunPowerShellCount(string pipeline)
    {
        var escaped = pipeline.Replace("'", "''", StringComparison.Ordinal);
        var output = RunPowerShellScalar($"try {{ (@({escaped}) | Measure-Object).Count }} catch {{ '-1' }}");
        return int.TryParse(output, out var count) ? count : -1;
    }

    private static string? RunPowerShellScalar(string command)
    {
        return RunCommand("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "`\"", StringComparison.Ordinal)}\"", TimeSpan.FromSeconds(15))
            ?.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault()
            ?.Trim();
    }

    private static string? RunCommand(string fileName, string arguments, TimeSpan timeout)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo(fileName, arguments)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            process.Start();
            if (!process.WaitForExit(Convert.ToInt32(timeout.TotalMilliseconds)))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // Process already exited.
                }

                return null;
            }

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            return string.IsNullOrWhiteSpace(stdout) ? stderr : stdout;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or ObjectDisposedException)
        {
            return null;
        }
    }

    private static (int Services, int Drivers, IReadOnlyList<string> ServiceNames) CountServicesAndDrivers()
    {
        var services = 0;
        var drivers = 0;
        var serviceNames = new List<string>();
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (key is null)
        {
            return (-1, -1, Array.Empty<string>());
        }

        foreach (var subkeyName in key.GetSubKeyNames())
        {
            using var subkey = key.OpenSubKey(subkeyName);
            var typeValue = subkey?.GetValue("Type");
            var type = typeValue is int intType ? intType : 0;
            if ((type & 0x30) != 0)
            {
                services++;
                serviceNames.Add(subkeyName);
            }
            else if ((type & 0x3) != 0)
            {
                drivers++;
            }
        }

        return (services, drivers, serviceNames);
    }

    private static int CountAutorunValues()
    {
        var paths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        };
        var count = 0;
        foreach (var path in paths)
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            count += key?.GetValueNames().Length ?? 0;
        }

        return count;
    }

    private static int CountInstalledSoftware()
    {
        var paths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };
        var count = 0;
        foreach (var path in paths)
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            if (key is null)
            {
                continue;
            }

            foreach (var subkeyName in key.GetSubKeyNames())
            {
                using var subkey = key.OpenSubKey(subkeyName);
                if (!string.IsNullOrWhiteSpace(Convert.ToString(subkey?.GetValue("DisplayName"), System.Globalization.CultureInfo.InvariantCulture)))
                {
                    count++;
                }
            }
        }

        return count;
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

    public static bool SubcategoryMeetsBaseline(string subcategory, string actual)
    {
        if (!RequiredSubcategories.TryGetValue(subcategory, out var required))
        {
            return true;
        }

        var needsSuccess = required.Contains("Success", StringComparison.OrdinalIgnoreCase);
        var needsFailure = required.Contains("Failure", StringComparison.OrdinalIgnoreCase);
        var hasSuccess = actual.Contains("Success", StringComparison.OrdinalIgnoreCase);
        var hasFailure = actual.Contains("Failure", StringComparison.OrdinalIgnoreCase);
        return (!needsSuccess || hasSuccess) && (!needsFailure || hasFailure);
    }

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
            || !SubcategoryMeetsBaseline(required.Key, actual));
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
