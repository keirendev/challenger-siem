using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Coverage;

public static class WindowsSourceManifest
{
    public static IReadOnlyList<SourceManifestEntry> L2Default => WindowsTelemetrySourceCatalog.L2Default;

    public static IReadOnlyList<SourceManifestEntry> SysmonL3 => WindowsTelemetrySourceCatalog.SysmonL3;

    public static IReadOnlyList<SourceManifestEntry> Build(IEnumerable<string> requiredChannels, IEnumerable<string> optionalChannels) =>
        WindowsTelemetrySourceCatalog.BuildManifest(requiredChannels, optionalChannels);

    public static IReadOnlyList<string> DefaultRequiredChannels() => WindowsTelemetrySourceCatalog.DefaultRequiredChannels();

    public static IReadOnlyList<string> DefaultOptionalChannels() => WindowsTelemetrySourceCatalog.DefaultOptionalChannels();
}
