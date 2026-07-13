using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Configuration;

public sealed class ManagedRetentionOptions
{
    public const string SectionName = "Storage:Retention";
    public const long HardManagedCapacityBytes = 100L * 1024 * 1024 * 1024;

    public bool Enabled { get; set; } = true;
    public bool HostedServiceEnabled { get; set; } = false;
    public int TargetRetentionDays { get; set; } = 30;
    public long ManagedCapacityBytes { get; set; } = HardManagedCapacityBytes;
    public int CleanupBatchSize { get; set; } = 500;
    public int MaxBatchesPerRun { get; set; } = 20;
    public int EmergencyTargetPercent { get; set; } = 95;
    public int HostedServiceIntervalMinutes { get; set; } = 60;
    public long AdvisoryLockKey { get; set; } = 197_301_100;
}

public sealed class ManagedRetentionOptionsValidator : IValidateOptions<ManagedRetentionOptions>
{
    public ValidateOptionsResult Validate(string? name, ManagedRetentionOptions options)
    {
        var failures = new List<string>();
        if (options.TargetRetentionDays is < 1 or > 3650) failures.Add("Storage:Retention:TargetRetentionDays must be between 1 and 3650.");
        if (options.ManagedCapacityBytes is < 1024 or > ManagedRetentionOptions.HardManagedCapacityBytes) failures.Add("Storage:Retention:ManagedCapacityBytes must be between 1024 bytes and the hard 100 GiB ceiling.");
        if (options.CleanupBatchSize is < 1 or > 10000) failures.Add("Storage:Retention:CleanupBatchSize must be between 1 and 10000.");
        if (options.MaxBatchesPerRun is < 1 or > 1000) failures.Add("Storage:Retention:MaxBatchesPerRun must be between 1 and 1000.");
        if (options.EmergencyTargetPercent is < 50 or > 99) failures.Add("Storage:Retention:EmergencyTargetPercent must be between 50 and 99.");
        if (options.HostedServiceIntervalMinutes is < 5 or > 1440) failures.Add("Storage:Retention:HostedServiceIntervalMinutes must be between 5 and 1440.");
        if (options.AdvisoryLockKey == 0) failures.Add("Storage:Retention:AdvisoryLockKey must be non-zero.");
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
