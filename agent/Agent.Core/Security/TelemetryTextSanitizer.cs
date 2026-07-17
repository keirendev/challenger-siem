using System.Text.RegularExpressions;

namespace Challenger.Siem.Agent.Core.Security;

public sealed record SanitizedTelemetryText(
    string Value,
    bool Truncated,
    bool InvalidText,
    bool Redacted,
    bool Dropped);

/// <summary>
/// Bounds untrusted telemetry text and best-effort redacts common credential-bearing forms.
/// This is deliberately not a guarantee that arbitrary secrets are removed; callers must still
/// avoid known secret sources and treat the resulting command metadata as sensitive telemetry.
/// </summary>
public static class TelemetryTextSanitizer
{
    private const string RedactionMarker = "<redacted>";
    private const string CredentialName =
        "(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|github[_-]?token|pgpassword|mysql[_-]?pwd|sshpass|password|passwd|pwd|token|api[_-]?key|secret|client[_-]?secret|access[_-]?key|authorization|proxy[_-]?authorization|cookie|connection[_-]?string|dsn|credential)";
    private const string LongCredentialOption =
        "(?:aws[-_]?secret[-_]?access[-_]?key|secret[-_]?access[-_]?key|password|passwd|token|api[-_]?key|secret|client[-_]?secret|access[-_]?key|authorization|cookie|connection[-_]?string|dsn)";
    private const string SensitiveHeaderName =
        "(?:(?:Proxy-)?Authorization|Cookie|X-Api-Key)";
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(50);
    private static readonly RegexOptions SafeRegexOptions = RegexOptions.CultureInvariant;

    // Header rules must run before generic assignment rules. Otherwise a quoted header such as
    // "Authorization: Bearer value" could redact only "Bearer" and leave the credential behind.
    private static readonly Regex QuotedDoubleHeaderPattern = Create(
        $@"(?<prefix>(?:^|\s)(?:-H(?:=|\s*)|--header(?:=|\s+))""\s*{SensitiveHeaderName}\s*:\s*)(?:\\.|[^""\\\r\n])*(?<suffix>"")",
        ignoreCase: true);
    private static readonly Regex QuotedSingleHeaderPattern = Create(
        $@"(?<prefix>(?:^|\s)(?:-H(?:=|\s*)|--header(?:=|\s+))'\s*{SensitiveHeaderName}\s*:\s*)(?:\\.|[^'\\\r\n])*(?<suffix>')",
        ignoreCase: true);
    private static readonly Regex UnquotedHeaderPattern = Create(
        $@"(?<prefix>(?:^|\s)(?:-H(?:=|\s*)|--header(?:=|\s+)){SensitiveHeaderName}\s*:\s*)(?:(?:Bearer|Basic)\s+)?[^\s""']+",
        ignoreCase: true);
    private static readonly Regex AuthorizationHeaderPattern = Create(
        @"(?<prefix>\b(?:Proxy-)?Authorization\s*:\s*)(?:Bearer|Basic)\s+[^\s""';,]+",
        ignoreCase: true);
    private static readonly Regex AuthorizationAssignmentOrOptionPattern = Create(
        @"(?<prefix>(?:\b(?:Proxy[_-]?)?Authorization\s*[:=]\s*|--authorization(?:=|\s+)))(?:Bearer|Basic)\s+[^\s""';,]+",
        ignoreCase: true);
    private static readonly Regex GenericSensitiveHeaderPattern = Create(
        $@"(?<prefix>\b{SensitiveHeaderName}\s*:(?>\s*))(?!{Regex.Escape(RedactionMarker)})[^\r\n""']+",
        ignoreCase: true);

    private static readonly Regex CurlUserDoublePattern = Create(
        @"(?<prefix>(?:^|\s)(?:-u(?:=|\s*)|--user(?:=|\s+))"")(?:(?:\\.|[^""\\:\r\n])*):(?:\\.|[^""\\\r\n])*(?<suffix>"")");
    private static readonly Regex CurlUserSinglePattern = Create(
        @"(?<prefix>(?:^|\s)(?:-u(?:=|\s*)|--user(?:=|\s+))')(?:(?:\\.|[^'\\:\r\n])*):(?:\\.|[^'\\\r\n])*(?<suffix>')");
    private static readonly Regex CurlUserUnquotedPattern = Create(
        @"(?<prefix>(?:^|\s)(?:-u(?:=|\s*)|--user(?:=|\s+)))[^\s:]*:[^\s]+");

    private static readonly Regex SshpassDoublePattern = Create(
        @"(?<prefix>\b(?i:sshpass)\b[^\r\n;|&]{0,256}?\s-(?:p|e)(?:=|\s+)?"")(?:\\.|[^""\\\r\n])*(?<suffix>"")");
    private static readonly Regex SshpassSinglePattern = Create(
        @"(?<prefix>\b(?i:sshpass)\b[^\r\n;|&]{0,256}?\s-(?:p|e)(?:=|\s+)?')(?:\\.|[^'\\\r\n])*(?<suffix>')");
    private static readonly Regex SshpassUnquotedPattern = Create(
        @"(?<prefix>\b(?i:sshpass)\b[^\r\n;|&]{0,256}?\s-(?:p|e)(?:=|\s+)?)[^\s""']+");

    // mysql's short password form is attached (-pVALUE). The separated -p form prompts and is
    // intentionally not guessed; --password with either '=' or a separate value is handled below.
    private static readonly Regex MysqlDoublePattern = Create(
        @"(?<prefix>\b(?i:mysql)\b[^\r\n;|&]{0,512}?\s-p"")(?:\\.|[^""\\\r\n])*(?<suffix>"")");
    private static readonly Regex MysqlSinglePattern = Create(
        @"(?<prefix>\b(?i:mysql)\b[^\r\n;|&]{0,512}?\s-p')(?:\\.|[^'\\\r\n])*(?<suffix>')");
    private static readonly Regex MysqlUnquotedPattern = Create(
        @"(?<prefix>\b(?i:mysql)\b[^\r\n;|&]{0,512}?\s-p)[^\s""']+");

    private static readonly Regex EntireDoubleQuotedAssignmentPattern = Create(
        $@"(?<prefix>""\s*{CredentialName}\s*[:=]\s*)(?:\\.|[^""\\\r\n])*(?<suffix>"")",
        ignoreCase: true);
    private static readonly Regex EntireSingleQuotedAssignmentPattern = Create(
        $@"(?<prefix>'\s*{CredentialName}\s*[:=]\s*)(?:\\.|[^'\\\r\n])*(?<suffix>')",
        ignoreCase: true);
    private static readonly Regex DoubleQuotedAssignmentPattern = Create(
        $@"(?<prefix>(?:[""']{CredentialName}[""']|{CredentialName})\s*[:=]\s*"")(?:\\.|[^""\\\r\n])*(?<suffix>"")",
        ignoreCase: true);
    private static readonly Regex SingleQuotedAssignmentPattern = Create(
        $@"(?<prefix>(?:[""']{CredentialName}[""']|{CredentialName})\s*[:=]\s*')(?:\\.|[^'\\\r\n])*(?<suffix>')",
        ignoreCase: true);
    private static readonly Regex UnquotedAssignmentPattern = Create(
        $@"(?<prefix>(?:[""']{CredentialName}[""']|{CredentialName})\s*[:=]\s*)[^\s;,""'}}\]]+",
        ignoreCase: true);

    private static readonly Regex DoubleQuotedLongOptionPattern = Create(
        $@"(?<prefix>--{LongCredentialOption}(?:=|\s+)"")(?:\\.|[^""\\\r\n])*(?<suffix>"")",
        ignoreCase: true);
    private static readonly Regex SingleQuotedLongOptionPattern = Create(
        $@"(?<prefix>--{LongCredentialOption}(?:=|\s+)')(?:\\.|[^'\\\r\n])*(?<suffix>')",
        ignoreCase: true);
    private static readonly Regex UnquotedLongOptionPattern = Create(
        $@"(?<prefix>--{LongCredentialOption}(?:=|\s+))[^\s;,""']+",
        ignoreCase: true);

    private static readonly Regex UriUserInfoPattern = Create(
        @"(?<prefix>\b[a-z][a-z0-9+.-]*://)[^/?#\s""']*:[^/?#\s""']*(?<suffix>@)",
        ignoreCase: true);

    public static SanitizedTelemetryText SanitizeAndRedact(string? value, int maxChars)
    {
        if (string.IsNullOrEmpty(value)) return new(string.Empty, false, false, false, false);
        if (maxChars < 1) throw new ArgumentOutOfRangeException(nameof(maxChars));

        var truncated = value.Length > maxChars;
        var invalid = ContainsInvalidOrControl(value);
        if (truncated || invalid)
        {
            return FailClosed(truncated, invalid);
        }

        // The common path is already within bounds and contains no control characters. Keep the
        // caller's string rather than allocating an identical bounded copy for every journal field.
        var bounded = value;
        var hasAssignmentDelimiter = bounded.Contains('=') || bounded.Contains(':');
        var hasLongOption = bounded.Contains("--", StringComparison.Ordinal);
        var hasHeaderOption = bounded.Contains("-H", StringComparison.Ordinal)
            || bounded.Contains("--header", StringComparison.Ordinal);
        var hasCurlUserOption = bounded.Contains("-u", StringComparison.Ordinal)
            || bounded.Contains("--user", StringComparison.Ordinal);
        var hasSshpass = bounded.Contains("sshpass", StringComparison.OrdinalIgnoreCase);
        var hasMysql = bounded.Contains("mysql", StringComparison.OrdinalIgnoreCase);
        var hasUri = bounded.Contains("://", StringComparison.Ordinal);
        var hasAuthorization = bounded.Contains("authorization", StringComparison.OrdinalIgnoreCase);
        var hasSensitiveHeader = hasAuthorization
            || bounded.Contains("cookie", StringComparison.OrdinalIgnoreCase)
            || bounded.Contains("x-api-key", StringComparison.OrdinalIgnoreCase);
        var hasCredentialSyntax = (hasAssignmentDelimiter || hasLongOption)
            && ContainsCredentialName(bounded);
        if (!hasHeaderOption
            && !hasCurlUserOption
            && !hasSshpass
            && !hasMysql
            && !hasUri
            && !hasSensitiveHeader
            && !hasCredentialSyntax)
        {
            return new(bounded, false, false, false, false);
        }

        try
        {
            var redacted = bounded;
            if (hasHeaderOption)
            {
                redacted = ReplaceWithQuotedMarker(QuotedDoubleHeaderPattern, redacted);
                redacted = ReplaceWithQuotedMarker(QuotedSingleHeaderPattern, redacted);
                redacted = ReplaceWithMarker(UnquotedHeaderPattern, redacted);
            }
            if (hasSensitiveHeader)
            {
                redacted = ReplaceWithMarker(GenericSensitiveHeaderPattern, redacted);
            }
            if (hasAuthorization)
            {
                redacted = ReplaceWithMarker(AuthorizationHeaderPattern, redacted);
                redacted = ReplaceWithMarker(AuthorizationAssignmentOrOptionPattern, redacted);
            }

            if (hasCurlUserOption)
            {
                redacted = ReplaceWithQuotedMarker(CurlUserDoublePattern, redacted);
                redacted = ReplaceWithQuotedMarker(CurlUserSinglePattern, redacted);
                redacted = ReplaceWithMarker(CurlUserUnquotedPattern, redacted);
            }
            if (hasSshpass)
            {
                redacted = ReplaceWithQuotedMarker(SshpassDoublePattern, redacted);
                redacted = ReplaceWithQuotedMarker(SshpassSinglePattern, redacted);
                redacted = ReplaceWithMarker(SshpassUnquotedPattern, redacted);
            }
            if (hasMysql)
            {
                redacted = ReplaceWithQuotedMarker(MysqlDoublePattern, redacted);
                redacted = ReplaceWithQuotedMarker(MysqlSinglePattern, redacted);
                redacted = ReplaceWithMarker(MysqlUnquotedPattern, redacted);
            }

            if (hasUri)
            {
                redacted = ReplaceWithQuotedMarker(UriUserInfoPattern, redacted);
            }
            if (hasCredentialSyntax && hasAssignmentDelimiter)
            {
                redacted = ReplaceWithQuotedMarker(EntireDoubleQuotedAssignmentPattern, redacted);
                redacted = ReplaceWithQuotedMarker(EntireSingleQuotedAssignmentPattern, redacted);
                redacted = ReplaceWithQuotedMarker(DoubleQuotedAssignmentPattern, redacted);
                redacted = ReplaceWithQuotedMarker(SingleQuotedAssignmentPattern, redacted);
                redacted = ReplaceWithMarker(UnquotedAssignmentPattern, redacted);
            }
            if (hasCredentialSyntax && hasLongOption)
            {
                redacted = ReplaceWithQuotedMarker(DoubleQuotedLongOptionPattern, redacted);
                redacted = ReplaceWithQuotedMarker(SingleQuotedLongOptionPattern, redacted);
                redacted = ReplaceWithMarker(UnquotedLongOptionPattern, redacted);
            }

            // A replacement marker can be longer than a short credential. Never let redaction
            // expand telemetry beyond its caller-provided bound.
            if (redacted.Length > maxChars)
            {
                return FailClosed(truncated: false, invalid: false);
            }

            return new(
                redacted,
                false,
                false,
                !string.Equals(redacted, bounded, StringComparison.Ordinal),
                false);
        }
        catch (RegexMatchTimeoutException)
        {
            return FailClosed(truncated: false, invalid: false);
        }
    }

    private static Regex Create(string pattern, bool ignoreCase = false) => new(
        pattern,
        ignoreCase ? SafeRegexOptions | RegexOptions.IgnoreCase : SafeRegexOptions,
        MatchTimeout);

    private static string ReplaceWithMarker(Regex pattern, string value) =>
        pattern.Replace(value, $"${{prefix}}{RedactionMarker}");

    private static string ReplaceWithQuotedMarker(Regex pattern, string value) =>
        pattern.Replace(value, $"${{prefix}}{RedactionMarker}${{suffix}}");

    private static SanitizedTelemetryText FailClosed(bool truncated, bool invalid) =>
        new(string.Empty, truncated, invalid, true, true);

    private static bool ContainsInvalidOrControl(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsControl(character)) return true;
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1])) return true;
                index++;
            }
            else if (char.IsLowSurrogate(character))
            {
                return true;
            }
        }
        return false;
    }

    private static bool ContainsCredentialName(string value) =>
        value.Contains("password", StringComparison.OrdinalIgnoreCase)
        || value.Contains("passwd", StringComparison.OrdinalIgnoreCase)
        || value.Contains("pwd", StringComparison.OrdinalIgnoreCase)
        || value.Contains("token", StringComparison.OrdinalIgnoreCase)
        || value.Contains("key", StringComparison.OrdinalIgnoreCase)
        || value.Contains("secret", StringComparison.OrdinalIgnoreCase)
        || value.Contains("dsn", StringComparison.OrdinalIgnoreCase)
        || value.Contains("sshpass", StringComparison.OrdinalIgnoreCase)
        || value.Contains("credential", StringComparison.OrdinalIgnoreCase)
        || value.Contains("connection", StringComparison.OrdinalIgnoreCase);
}
