using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class RazorVersionRenderingTests
{
    [Theory]
    [InlineData("Detections/Index.cshtml", "v@(item.Rule.Version)", "v@item.Rule.Version")]
    [InlineData("Alerts/Index.cshtml", "v@(alert.RuleVersion)", "v@alert.RuleVersion")]
    [InlineData("Alerts/Detail.cshtml", "v@(Model.Alert.RuleVersion)", "v@Model.Alert.RuleVersion")]
    [InlineData("Events/Index.cshtml", "v@(saved.Version)", "v@saved.Version")]
    public void VersionLabelsUseExplicitRazorExpressions(
        string relativePath,
        string expectedExpression,
        string literalTemplateToken)
    {
        var markup = File.ReadAllText(RepositoryPath("server", "Siem.Api", "Pages", relativePath));

        Assert.Contains(expectedExpression, markup, StringComparison.Ordinal);
        Assert.DoesNotContain(literalTemplateToken, markup, StringComparison.Ordinal);
    }

    private static string RepositoryPath(params string[] parts)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln")))
        {
            current = current.Parent;
        }

        return Path.Combine(
            new[] { current?.FullName ?? throw new InvalidOperationException("Repository root not found.") }
                .Concat(parts)
                .ToArray());
    }
}
