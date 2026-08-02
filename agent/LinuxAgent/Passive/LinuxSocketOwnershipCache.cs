namespace Challenger.Siem.LinuxAgent.Passive;

public sealed record LinuxSocketOwnershipSnapshot(
    DateTimeOffset ObservedAt,
    IReadOnlyDictionary<long, IReadOnlyList<LinuxSocketOwner>> Owners,
    bool Complete,
    bool DescriptorCapReached,
    bool PermissionDenied,
    long DescriptorLinksInspected);

public sealed class LinuxSocketOwnershipCache(TimeProvider timeProvider)
{
    public const int MaxDescriptorsPerProcess = 256;
    public const int MaxDescriptorLinksPerScan = 32_768;
    public const int MaxOwnersPerSocket = 4;

    private LinuxSocketOwnershipSnapshot? current;

    public LinuxSocketOwnershipSnapshot? Current => Volatile.Read(ref current);

    public void Publish(
        IReadOnlyDictionary<long, IReadOnlyList<LinuxSocketOwner>> owners,
        bool complete,
        bool descriptorCapReached,
        bool permissionDenied,
        long descriptorLinksInspected) =>
        Volatile.Write(ref current, new(
            timeProvider.GetUtcNow(), owners, complete, descriptorCapReached, permissionDenied, descriptorLinksInspected));

    public static bool TryParseSocketTarget(string? target, out long inode)
    {
        inode = 0;
        return target is { Length: >= 10 and <= 40 }
            && target.StartsWith("socket:[", StringComparison.Ordinal)
            && target.EndsWith(']')
            && long.TryParse(target.AsSpan(8, target.Length - 9), out inode)
            && inode > 0;
    }
}
