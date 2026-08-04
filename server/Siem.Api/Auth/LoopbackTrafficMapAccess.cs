using System.Net;
using System.Security.Claims;
using Challenger.Siem.Api.Configuration;

namespace Challenger.Siem.Api.Auth;

public static class LoopbackTrafficMapAccess
{
    public const string PrincipalName = "traffic-map-loopback";
    public const string AuthenticationType = "LoopbackTrafficMap";

    public static bool CanImplyAuthentication(HttpContext context, TrafficMapOptions options) =>
        options.Enabled
        && IsDashboardDataPath(context.Request.Path)
        && IsDirectLoopbackRequest(context)
        && string.IsNullOrEmpty(context.Request.Headers.Authorization);

    public static bool CanServeUi(HttpContext context, TrafficMapOptions options) =>
        options.Enabled
        && context.Request.Path.StartsWithSegments("/ui", StringComparison.OrdinalIgnoreCase)
        && IsDirectLoopbackRequest(context);

    public static bool IsDashboardDataPath(PathString path) =>
        path.Equals("/api/v2/network/geography", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/api/v2/network/geography/events", StringComparison.OrdinalIgnoreCase);

    public static ClaimsPrincipal Principal()
    {
        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.Name, PrincipalName),
                new Claim(ClaimTypes.Role, ServiceRoles.Service),
                new Claim("service_id", ServiceAuthentication.ServiceId.ToString()),
                new Claim("authentication_mode", "direct_loopback")
            },
            AuthenticationType);
        return new ClaimsPrincipal(identity);
    }

    private static bool IsDirectLoopbackRequest(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method)) return false;
        if (!IsLoopback(context.Connection.RemoteIpAddress) || !IsLoopback(context.Connection.LocalIpAddress)) return false;
        if (!IsLoopbackHost(context.Request.Host.Host)) return false;
        return !HasForwardingHeaders(context.Request.Headers);
    }

    private static bool IsLoopback(IPAddress? address)
    {
        if (address is null) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return IPAddress.IsLoopback(address);
    }

    private static bool IsLoopbackHost(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
        || IPAddress.TryParse(host.Trim('[', ']'), out var address) && IsLoopback(address);

    private static bool HasForwardingHeaders(IHeaderDictionary headers) =>
        headers.Keys.Any(key => key.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase))
        || headers.ContainsKey("Forwarded")
        || headers.ContainsKey("X-Real-IP")
        || headers.ContainsKey("X-Original-For")
        || headers.ContainsKey("X-Original-Host")
        || headers.ContainsKey("CF-Connecting-IP")
        || headers.ContainsKey("True-Client-IP");
}
