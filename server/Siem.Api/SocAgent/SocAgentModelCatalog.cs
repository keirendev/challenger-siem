using System.Text.RegularExpressions;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.SocAgent;

public sealed record SocAgentExecutionSelection(string Model, string? ReasoningEffort);

public sealed class SocAgentSelectionException(string field, string operatorSafeMessage)
    : ArgumentException(operatorSafeMessage)
{
    public string Field { get; } = field;
}

public static partial class SocAgentModelCatalog
{
    private static readonly HashSet<string> SupportedEfforts = new(StringComparer.OrdinalIgnoreCase)
    {
        "none", "minimal", "low", "medium", "high", "xhigh", "max"
    };

    public static SocAgentProviderStatusResponse AddOptions(
        SocAgentProviderStatusResponse status,
        SocAgentOptions options)
    {
        var modelOptions = BuildOptions(status, options);
        var selected = modelOptions.FirstOrDefault(option => option.Model.Equals(status.Model, StringComparison.OrdinalIgnoreCase))
            ?? modelOptions[0];
        return status with
        {
            Model = selected.Model,
            ReasoningEffort = selected.DefaultReasoningEffort,
            ModelOptions = modelOptions
        };
    }

    public static SocAgentExecutionSelection Resolve(
        SocAgentProviderStatusResponse status,
        string? requestedModel,
        string? requestedEffort)
    {
        var model = string.IsNullOrWhiteSpace(requestedModel) ? status.Model : requestedModel.Trim();
        var option = status.ModelOptions.FirstOrDefault(candidate => candidate.Model.Equals(model, StringComparison.OrdinalIgnoreCase));
        if (option is null)
        {
            throw new SocAgentSelectionException("model", "The selected soc-agent model is not available in the server allowlist.");
        }

        if (option.ReasoningEfforts.Count == 0)
        {
            if (!string.IsNullOrWhiteSpace(requestedEffort))
            {
                throw new SocAgentSelectionException("reasoning_effort", "Reasoning effort is not available for the selected soc-agent model.");
            }

            return new SocAgentExecutionSelection(option.Model, null);
        }

        var effort = string.IsNullOrWhiteSpace(requestedEffort)
            ? option.DefaultReasoningEffort
            : requestedEffort.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(effort)
            || !option.ReasoningEfforts.Contains(effort, StringComparer.OrdinalIgnoreCase))
        {
            throw new SocAgentSelectionException("reasoning_effort", "The selected reasoning effort is not available for the selected soc-agent model.");
        }

        return new SocAgentExecutionSelection(option.Model, effort.ToLowerInvariant());
    }

    public static bool Supports(
        SocAgentProviderStatusResponse status,
        string? model,
        string? reasoningEffort)
    {
        try
        {
            Resolve(status, model, reasoningEffort);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static IReadOnlyList<SocAgentModelOption> BuildOptions(
        SocAgentProviderStatusResponse status,
        SocAgentOptions options)
    {
        var configured = new List<SocAgentConfiguredModelOption>();
        configured.AddRange(options.ModelOptions ?? []);
        if (!configured.Any(option => string.Equals(option.Model, options.Model, StringComparison.OrdinalIgnoreCase)))
        {
            configured.Insert(0, new SocAgentConfiguredModelOption
            {
                Model = options.Model,
                DisplayName = options.Model,
                ReasoningEfforts = options.ReasoningEfforts ?? [],
                DefaultReasoningEffort = options.ReasoningEffort
            });
        }

        var isLocal = status.Provider.Equals("Local", StringComparison.OrdinalIgnoreCase);
        var result = new List<SocAgentModelOption>();
        foreach (var configuredOption in configured.Take(20))
        {
            var model = configuredOption.Model?.Trim() ?? string.Empty;
            if (!ModelIdRegex().IsMatch(model)
                || result.Any(option => option.Model.Equals(model, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var efforts = isLocal
                ? Array.Empty<string>()
                : (configuredOption.ReasoningEfforts ?? [])
                    .Select(value => value?.Trim().ToLowerInvariant())
                    .Where(value => !string.IsNullOrWhiteSpace(value) && SupportedEfforts.Contains(value))
                    .Select(value => value!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(7)
                    .ToArray();
            var defaultEffort = NormalizeDefaultEffort(configuredOption.DefaultReasoningEffort, efforts);
            result.Add(new SocAgentModelOption
            {
                Model = model,
                DisplayName = NormalizeDisplayName(configuredOption.DisplayName, model),
                ReasoningEfforts = efforts,
                DefaultReasoningEffort = defaultEffort
            });
        }

        if (result.Count == 0)
        {
            var configuredModel = options.Model?.Trim() ?? string.Empty;
            var fallbackModel = ModelIdRegex().IsMatch(configuredModel)
                ? configuredModel
                : "soc-agent-local-v1";
            result.Add(new SocAgentModelOption
            {
                Model = fallbackModel,
                DisplayName = fallbackModel,
                ReasoningEfforts = Array.Empty<string>()
            });
        }

        return result;
    }

    private static string? NormalizeDefaultEffort(string? configured, IReadOnlyList<string> efforts)
    {
        if (efforts.Count == 0)
        {
            return null;
        }

        var normalized = configured?.Trim().ToLowerInvariant();
        return !string.IsNullOrWhiteSpace(normalized) && efforts.Contains(normalized, StringComparer.OrdinalIgnoreCase)
            ? normalized
            : efforts[0];
    }

    private static string NormalizeDisplayName(string? displayName, string model)
    {
        var value = string.IsNullOrWhiteSpace(displayName) ? model : displayName.Trim();
        return value.Length <= 80 ? value : value[..80];
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex ModelIdRegex();
}
