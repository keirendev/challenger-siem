using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Pages;
using Challenger.Siem.Api.SocAgent;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class SocAgentSubscriptionOAuthConnectTests
{
    private static readonly Guid AdminOperatorId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private const string AdminSessionToken = "synthetic-admin-browser-session-token";

    [Fact]
    public void CreateAuthorizationUriUsesOfficialEndpointPkceAndCorrelationCookie()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath);
        var context = CreateContext();

        var uri = service.CreateAuthorizationUri(context, "/soc-agent");
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);

        Assert.Equal("auth.openai.com", uri.Host);
        Assert.Equal("/oauth/authorize", uri.AbsolutePath);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("synthetic-client-id", query["client_id"]);
        Assert.Equal("http://127.0.0.1:5081/soc-agent/oauth/callback", query["redirect_uri"]);
        Assert.Contains("model.request", query["scope"].ToString(), StringComparison.Ordinal);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.False(string.IsNullOrWhiteSpace(query["code_challenge"]));
        Assert.False(string.IsNullOrWhiteSpace(query["state"]));
        Assert.Contains(".ChallengerSiem.SocAgentOAuth=", context.Response.Headers.SetCookie.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-client-secret", context.Response.Headers.SetCookie.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(AdminSessionToken, context.Response.Headers.SetCookie.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompleteAsyncExchangesCodeAndStoresMinimalServerSideCredentialFile()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(request =>
        {
            Assert.Equal(new Uri("https://auth.openai.com/oauth/token"), request.RequestUri);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""
                {
                  "access_token": "synthetic-connected-access-token",
                  "refresh_token": "synthetic-connected-refresh-token",
                  "token_type": "Bearer",
                  "expires_in": 3600,
                  "scope": "openid profile offline_access model.request",
                  "id_token": "synthetic-id-token-that-must-not-be-stored"
                }
                """)
            };
        }));
        var protector = new EphemeralDataProtectionProvider();
        var service = CreateService(httpClient, authFile.FilePath, protector);
        var startContext = CreateContext();
        var uri = service.CreateAuthorizationUri(startContext, "/soc-agent");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query)["state"].ToString();
        var callbackContext = CreateContext($"/soc-agent/oauth/callback?code=synthetic-code&state={Uri.EscapeDataString(state)}");
        callbackContext.User = new ClaimsPrincipal(new ClaimsIdentity());
        callbackContext.Request.Headers.Cookie = ExtractCookieHeader(startContext.Response.Headers.SetCookie.ToString());

        var result = await service.CompleteAsync(callbackContext, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal("connected", result.Status);
        var saved = File.ReadAllText(authFile.FilePath);
        Assert.Contains("synthetic-connected-access-token", saved, StringComparison.Ordinal);
        Assert.Contains("synthetic-connected-refresh-token", saved, StringComparison.Ordinal);
        Assert.Contains("subscription_oauth", saved, StringComparison.Ordinal);
        Assert.Contains("model.request", saved, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-id-token-that-must-not-be-stored", saved, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-client-secret", saved, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompleteAsyncRejectsOversizedTokenResponseWithoutWritingCredentialFile()
    {
        using var authFile = SyntheticAuthFile.Create();
        var oversizedResponse = JsonSerializer.Serialize(new
        {
            access_token = "synthetic-connected-access-token",
            padding = new string('x', (256 * 1024) + 1)
        });
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(oversizedResponse)
        }));
        var protector = new EphemeralDataProtectionProvider();
        var service = CreateService(httpClient, authFile.FilePath, protector);
        var startContext = CreateContext();
        var uri = service.CreateAuthorizationUri(startContext, "/soc-agent");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query)["state"].ToString();
        var callbackContext = CreateContext($"/soc-agent/oauth/callback?code=synthetic-code&state={Uri.EscapeDataString(state)}");
        callbackContext.User = new ClaimsPrincipal(new ClaimsIdentity());
        callbackContext.Request.Headers.Cookie = ExtractCookieHeader(startContext.Response.Headers.SetCookie.ToString());

        var exception = await Assert.ThrowsAsync<SocAgentSubscriptionOAuthConnectException>(() =>
            service.CompleteAsync(callbackContext, CancellationToken.None));

        Assert.Equal("provider_error", exception.Status);
        Assert.Contains("safety limit", exception.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("synthetic-connected-access-token", exception.OperatorSafeMessage, StringComparison.Ordinal);
        Assert.False(File.Exists(authFile.FilePath));
    }

    [Fact]
    public async Task AdvancedOAuthPageHandlersDenyAnalystAndAllowAdmin()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath);

        var analystContext = CreateContext(role: OperatorRoles.Analyst);
        var analystPage = CreatePageModel(service, analystContext);
        Assert.False(analystPage.CanStartSubscriptionOAuthConnect);
        Assert.IsType<ForbidResult>(analystPage.OnPostConnectSubscriptionOAuth());
        Assert.IsType<ForbidResult>(await analystPage.OnPostDisconnectSubscriptionOAuthAsync(CancellationToken.None));

        var adminContext = CreateContext();
        var adminPage = CreatePageModel(service, adminContext);
        Assert.True(adminPage.CanStartSubscriptionOAuthConnect);
        var connect = Assert.IsType<RedirectResult>(adminPage.OnPostConnectSubscriptionOAuth());
        Assert.StartsWith("https://auth.openai.com/oauth/authorize", connect.Url, StringComparison.Ordinal);

        adminPage.ConfirmSubscriptionDisconnect = false;
        Assert.IsType<RedirectToPageResult>(await adminPage.OnPostDisconnectSubscriptionOAuthAsync(CancellationToken.None));
    }

    [Fact]
    public void CreateAuthorizationUriRejectsNonAdminOrNonBrowserSession()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath);

        var analyst = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() =>
            service.CreateAuthorizationUri(CreateContext(role: OperatorRoles.Analyst), "/soc-agent"));
        Assert.Equal("auth_required", analyst.Status);
        Assert.Contains("admin browser session", analyst.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);

        var bearerOnlyAdmin = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() =>
            service.CreateAuthorizationUri(CreateContext(role: OperatorRoles.Admin, sessionToken: null), "/soc-agent"));
        Assert.Equal("auth_required", bearerOnlyAdmin.Status);
        Assert.DoesNotContain(AdminSessionToken, bearerOnlyAdmin.OperatorSafeMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompleteAsyncRejectsRevokedInitiatingSessionBeforeTokenExchange()
    {
        using var authFile = SyntheticAuthFile.Create();
        var tokenEndpointCalled = false;
        using var httpClient = new HttpClient(new RecordingHandler(_ =>
        {
            tokenEndpointCalled = true;
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        var protector = new EphemeralDataProtectionProvider();
        var service = CreateService(
            httpClient,
            authFile.FilePath,
            protector,
            sessionValidator: new FakeOperatorSessionValidator(_ => null));
        var startContext = CreateContext();
        var uri = service.CreateAuthorizationUri(startContext, "/soc-agent");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query)["state"].ToString();
        var callbackContext = CreateContext($"/soc-agent/oauth/callback?code=synthetic-code&state={Uri.EscapeDataString(state)}");
        callbackContext.User = new ClaimsPrincipal(new ClaimsIdentity());
        callbackContext.Request.Headers.Cookie = ExtractCookieHeader(startContext.Response.Headers.SetCookie.ToString());

        var result = await service.CompleteAsync(callbackContext, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal("auth_required", result.Status);
        Assert.Contains("initiating admin session", result.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.False(tokenEndpointCalled);
        Assert.False(File.Exists(authFile.FilePath));
        Assert.DoesNotContain(AdminSessionToken, result.OperatorSafeMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompleteAsyncRejectsMismatchedStateBeforeSessionOrTokenProcessing()
    {
        using var authFile = SyntheticAuthFile.Create();
        var tokenEndpointCalled = false;
        var sessionValidatorCalled = false;
        using var httpClient = new HttpClient(new RecordingHandler(_ =>
        {
            tokenEndpointCalled = true;
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        var protector = new EphemeralDataProtectionProvider();
        var service = CreateService(
            httpClient,
            authFile.FilePath,
            protector,
            sessionValidator: new FakeOperatorSessionValidator(_ =>
            {
                sessionValidatorCalled = true;
                return CreateOperatorSession(AdminOperatorId, OperatorRoles.Admin);
            }));
        var startContext = CreateContext();
        _ = service.CreateAuthorizationUri(startContext, "/soc-agent");
        var callbackContext = CreateContext("/soc-agent/oauth/callback?code=synthetic-code&state=synthetic-wrong-state");
        callbackContext.User = new ClaimsPrincipal(new ClaimsIdentity());
        callbackContext.Request.Headers.Cookie = ExtractCookieHeader(startContext.Response.Headers.SetCookie.ToString());

        var result = await service.CompleteAsync(callbackContext, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal("auth_required", result.Status);
        Assert.Contains("state check failed", result.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.False(sessionValidatorCalled);
        Assert.False(tokenEndpointCalled);
        Assert.False(File.Exists(authFile.FilePath));
    }

    [Fact]
    public async Task CompleteAsyncRejectsDifferentAuthenticatedBrowserSession()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var protector = new EphemeralDataProtectionProvider();
        var service = CreateService(httpClient, authFile.FilePath, protector);
        var startContext = CreateContext();
        var uri = service.CreateAuthorizationUri(startContext, "/soc-agent");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query)["state"].ToString();
        var callbackContext = CreateContext(
            $"/soc-agent/oauth/callback?code=synthetic-code&state={Uri.EscapeDataString(state)}",
            role: OperatorRoles.Admin,
            operatorId: Guid.Parse("22222222-2222-2222-2222-222222222222"),
            sessionToken: "synthetic-different-admin-session-token");
        callbackContext.Request.Headers.Cookie = ExtractCookieHeader(startContext.Response.Headers.SetCookie.ToString());

        var result = await service.CompleteAsync(callbackContext, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal("auth_required", result.Status);
        Assert.DoesNotContain("synthetic-different-admin-session-token", result.OperatorSafeMessage, StringComparison.Ordinal);
        Assert.False(File.Exists(authFile.FilePath));
    }

    [Fact]
    public void CreateAuthorizationUriRejectsReservedCodexManagedProviderTarget()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath, options =>
        {
            options.SubscriptionAuthFileProviderKey = "openai-codex";
        });

        var ex = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() => service.CreateAuthorizationUri(CreateContext(), "/soc-agent"));

        Assert.Equal("provider_error", ex.Status);
        Assert.Contains("reserved Codex-managed", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SIEM-managed ChatGPT login", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(".codex")]
    [InlineData(".pi")]
    public void CreateAuthorizationUriRejectsGlobalManagedCredentialState(string managedDirectory)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(userProfile))
        {
            return;
        }

        var reservedPath = Path.Combine(userProfile, managedDirectory, "auth.json");
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, reservedPath);

        var ex = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() =>
            service.CreateAuthorizationUri(CreateContext(), "/soc-agent"));

        Assert.Equal("provider_error", ex.Status);
        Assert.Contains("global Codex or Pi credential state", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(reservedPath, ex.OperatorSafeMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(".codex")]
    [InlineData(".pi")]
    public void LegacyCredentialPathsRejectLocalAliasToGlobalManagedState(string managedDirectory)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(userProfile))
        {
            return;
        }

        var testRoot = Path.Combine(
            Path.GetTempPath(),
            "challenger-siem-tests",
            $"linked-credential-{Guid.NewGuid():N}");
        var localDirectory = Path.Combine(testRoot, ".local");
        var aliasPath = Path.Combine(localDirectory, "alias");
        var managedRoot = Path.Combine(userProfile, managedDirectory);
        var credentialFileName = $"challenger-siem-synthetic-{Guid.NewGuid():N}.auth.json";
        var configuredPath = Path.Combine(aliasPath, credentialFileName);
        var managedTarget = Path.Combine(managedRoot, credentialFileName);
        Directory.CreateDirectory(localDirectory);
        Directory.CreateSymbolicLink(aliasPath, managedRoot);
        Assert.False(File.Exists(managedTarget));

        try
        {
            using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
            var service = CreateService(httpClient, configuredPath);
            Assert.False(service.CanStartInteractiveConnect());

            var exception = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() =>
                service.CreateAuthorizationUri(CreateContext(), "/soc-agent"));
            Assert.Equal("provider_error", exception.Status);
            Assert.Contains("no linked or reparse-point", exception.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);

            var options = new SocAgentOptions
            {
                Provider = "ChatGPT",
                AuthMode = "SubscriptionOAuth",
                ExternalCallsEnabled = true,
                SubscriptionAuthFilePath = configuredPath,
                SubscriptionAuthFileProviderKey = "chatgpt"
            };
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>())
                .Build();
            var loadResult = SocAgentSubscriptionOAuthCredentialLoader.Load(
                options,
                configuration,
                includeSecret: false);

            Assert.Equal("provider_error", loadResult.Status);
            Assert.DoesNotContain(configuredPath, loadResult.OperatorMessage, StringComparison.Ordinal);
            Assert.False(File.Exists(managedTarget));
        }
        finally
        {
            DeleteDirectoryLink(aliasPath);
            if (Directory.Exists(testRoot))
            {
                Directory.Delete(testRoot, recursive: true);
            }
        }

        Assert.False(File.Exists(managedTarget));
    }

    [Fact]
    public void LegacySubscriptionLoaderRejectsReservedCodexManagedProviderEntry()
    {
        var options = new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = Path.Combine(Path.GetTempPath(), "synthetic-dedicated-auth.json"),
            SubscriptionAuthFileProviderKey = "openai-codex"
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        var result = SocAgentSubscriptionOAuthCredentialLoader.Load(options, configuration, includeSecret: false);

        Assert.Equal("provider_error", result.Status);
        Assert.Contains("reserved for SIEM-managed Codex authentication", result.OperatorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(options.SubscriptionAuthFilePath, result.OperatorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateAuthorizationUriRejectsNonOfficialAuthorizationEndpoint()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath, options =>
        {
            options.SubscriptionAuthorizationUrl = "https://example.invalid/oauth/authorize";
        });

        var ex = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() => service.CreateAuthorizationUri(CreateContext(), "/soc-agent"));

        Assert.Equal("provider_error", ex.Status);
        Assert.Contains("official authorization URL", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://auth.openai.com:444/oauth/authorize")]
    [InlineData("https://operator@auth.openai.com/oauth/authorize")]
    [InlineData("https://auth.openai.com/oauth/authorize?route=other")]
    [InlineData("https://auth.openai.com/oauth/authorize#fragment")]
    public void CreateAuthorizationUriRejectsNonExactOfficialAuthorizationEndpoint(string endpoint)
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath, options =>
        {
            options.SubscriptionAuthorizationUrl = endpoint;
        });

        var exception = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() =>
            service.CreateAuthorizationUri(CreateContext(), "/soc-agent"));

        Assert.Equal("provider_error", exception.Status);
        Assert.Contains("official authorization URL", exception.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://auth.openai.com:444/oauth/token")]
    [InlineData("https://operator@auth.openai.com/oauth/token")]
    [InlineData("https://auth.openai.com/oauth/token?route=other")]
    [InlineData("https://auth.openai.com/oauth/token#fragment")]
    public async Task CompleteAsyncRejectsNonExactOfficialTokenEndpointBeforeExchange(string endpoint)
    {
        using var authFile = SyntheticAuthFile.Create();
        var tokenEndpointCalled = false;
        using var httpClient = new HttpClient(new RecordingHandler(_ =>
        {
            tokenEndpointCalled = true;
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        var protector = new EphemeralDataProtectionProvider();
        var service = CreateService(httpClient, authFile.FilePath, protector, options =>
        {
            options.SubscriptionTokenEndpoint = endpoint;
        });
        var startContext = CreateContext();
        var authorizationUri = service.CreateAuthorizationUri(startContext, "/soc-agent");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(authorizationUri.Query)["state"].ToString();
        var callbackContext = CreateContext($"/soc-agent/oauth/callback?code=synthetic-code&state={Uri.EscapeDataString(state)}");
        callbackContext.User = new ClaimsPrincipal(new ClaimsIdentity());
        callbackContext.Request.Headers.Cookie = ExtractCookieHeader(startContext.Response.Headers.SetCookie.ToString());

        var result = await service.CompleteAsync(callbackContext, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal("provider_error", result.Status);
        Assert.False(tokenEndpointCalled);
        Assert.False(File.Exists(authFile.FilePath));
    }

    [Theory]
    [InlineData("https://auth.openai.com:444/")]
    [InlineData("https://operator@auth.openai.com/")]
    [InlineData("https://auth.openai.com/?issuer=other")]
    [InlineData("https://auth.openai.com/#fragment")]
    [InlineData("https://auth.openai.com/tenant")]
    public void LegacySubscriptionLoaderRejectsNonExactOfficialIssuer(string issuer)
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write(SubscriptionCredentialJson(
            issuer,
            "https://auth.openai.com/oauth/token",
            DateTimeOffset.UtcNow.AddHours(1)));
        var options = new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();

        var result = SocAgentSubscriptionOAuthCredentialLoader.Load(options, configuration, includeSecret: false);

        Assert.Equal("unsupported_subscription_oauth", result.Status);
        Assert.Contains("issuer", result.OperatorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://auth.openai.com:444/oauth/token")]
    [InlineData("https://operator@auth.openai.com/oauth/token")]
    [InlineData("https://auth.openai.com/oauth/token?route=other")]
    [InlineData("https://auth.openai.com/oauth/token#fragment")]
    public void LegacySubscriptionLoaderRejectsNonExactRefreshEndpoint(string endpoint)
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write(SubscriptionCredentialJson(
            "https://auth.openai.com/",
            endpoint,
            DateTimeOffset.UtcNow.AddMinutes(1)));
        var options = new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath,
            AuthFileExpirySkewSeconds = 300
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();

        var result = SocAgentSubscriptionOAuthCredentialLoader.Load(options, configuration, includeSecret: false);

        Assert.Equal("refresh_failed", result.Status);
        Assert.Equal("not_supported", result.RefreshStatus);
        Assert.Contains("no official allowlisted refresh endpoint", result.OperatorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LegacySubscriptionRefreshUpdatesNestedTopLevelProviderEntryInPlace()
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write(TopLevelSubscriptionCredentialJson(DateTimeOffset.UtcNow.AddMinutes(1)));
        var options = new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath,
            SubscriptionAuthFileProviderKey = "chatgpt",
            SubscriptionRequiredScopes = "model.request",
            AuthFileExpirySkewSeconds = 300
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();
        var credential = SocAgentSubscriptionOAuthCredentialLoader.Load(
            options,
            configuration,
            includeSecret: true);
        Assert.Equal("connected", credential.Status);
        Assert.True(credential.ShouldRefresh());

        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
            {
              "access_token": "synthetic-refreshed-top-level-access-token",
              "refresh_token": "synthetic-refreshed-top-level-refresh-token",
              "token_type": "Bearer",
              "expires_in": 3600,
              "scope": "model.request"
            }
            """)
        }));

        var refreshed = await SocAgentSubscriptionOAuthCredentialLoader.RefreshAsync(
            credential,
            options,
            httpClient,
            CancellationToken.None);

        Assert.Equal("synthetic-refreshed-top-level-access-token", refreshed.AccessToken);
        using var saved = JsonDocument.Parse(File.ReadAllText(authFile.FilePath));
        var root = saved.RootElement;
        Assert.Equal(7, root.GetProperty("schema_version").GetInt32());
        Assert.False(root.TryGetProperty("access_token", out _));
        Assert.False(root.TryGetProperty("refresh_token", out _));
        var entry = root.GetProperty("chatgpt");
        Assert.Equal("preserve-top-level-entry", entry.GetProperty("custom").GetString());
        Assert.Equal(
            "synthetic-refreshed-top-level-access-token",
            entry.GetProperty("access_token").GetString());
        Assert.Equal(
            "synthetic-refreshed-top-level-refresh-token",
            entry.GetProperty("refresh_token").GetString());
    }

    [Fact]
    public async Task LegacySubscriptionRefreshRejectsOversizedResponseWithoutChangingCredentialFile()
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write(TopLevelSubscriptionCredentialJson(DateTimeOffset.UtcNow.AddMinutes(1)));
        var original = File.ReadAllText(authFile.FilePath);
        var options = new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath,
            SubscriptionAuthFileProviderKey = "chatgpt",
            SubscriptionRequiredScopes = "model.request",
            AuthFileExpirySkewSeconds = 300
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();
        var credential = SocAgentSubscriptionOAuthCredentialLoader.Load(
            options,
            configuration,
            includeSecret: true);
        var oversizedResponse = JsonSerializer.Serialize(new
        {
            access_token = "synthetic-refreshed-access-token",
            padding = new string('x', (256 * 1024) + 1)
        });
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(oversizedResponse)
        }));

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            SocAgentSubscriptionOAuthCredentialLoader.RefreshAsync(
                credential,
                options,
                httpClient,
                CancellationToken.None));

        Assert.Equal("refresh_failed", exception.ErrorCode);
        Assert.Contains("safety limit", exception.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("synthetic-refreshed-access-token", exception.OperatorSafeMessage, StringComparison.Ordinal);
        Assert.Equal(original, File.ReadAllText(authFile.FilePath));
    }

    [Fact]
    public async Task DisconnectAsyncRequiresConfirmationWithoutChangingCredentialFile()
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write(DedicatedCredentialJson());
        var original = File.ReadAllText(authFile.FilePath);
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath);

        var result = await service.DisconnectAsync(confirmed: false, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.False(result.Removed);
        Assert.Equal("confirmation_required", result.Status);
        Assert.Equal(original, File.ReadAllText(authFile.FilePath));
        AssertSafeDisconnectResult(result, authFile.FilePath, "synthetic-target-access-token");
    }

    [Fact]
    public async Task DisconnectAsyncRemovesOnlyConfiguredDedicatedEntryAndWritesRestrictedFileAtomically()
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write(DedicatedCredentialJson());
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath, options =>
        {
            options.SubscriptionAuthFileProviderKey = "CHATGPT";
        });

        Assert.True(service.CanDisconnectDedicatedCredential());
        var result = await service.DisconnectAsync(confirmed: true, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.True(result.Removed);
        Assert.Equal("disconnected", result.Status);
        using var saved = JsonDocument.Parse(File.ReadAllText(authFile.FilePath));
        var root = saved.RootElement;
        Assert.Equal(7, root.GetProperty("schema_version").GetInt32());
        Assert.Equal("preserve-this", root.GetProperty("metadata").GetProperty("label").GetString());
        var providers = root.GetProperty("providers");
        Assert.False(providers.TryGetProperty("chatgpt", out _));
        Assert.Equal(
            "synthetic-preserved-access-token",
            providers.GetProperty("another-provider").GetProperty("access_token").GetString());
        Assert.Equal("preserve-provider-field", providers.GetProperty("another-provider").GetProperty("custom").GetString());
        Assert.False(service.CanDisconnectDedicatedCredential());
        var files = Directory.GetFiles(authFile.DirectoryPath);
        Assert.Single(files);
        Assert.Equal(authFile.FilePath, files[0]);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(authFile.FilePath));
        }

        AssertSafeDisconnectResult(
            result,
            authFile.FilePath,
            "synthetic-target-access-token",
            "synthetic-target-refresh-token",
            "synthetic-preserved-access-token");
    }

    [Fact]
    public async Task DisconnectAsyncRefusesReservedCodexManagedProviderTarget()
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write(DedicatedCredentialJson());
        var original = File.ReadAllText(authFile.FilePath);
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath, options =>
        {
            options.SubscriptionAuthFileProviderKey = "openai-codex";
        });

        Assert.False(service.CanDisconnectDedicatedCredential());
        var result = await service.DisconnectAsync(confirmed: true, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.False(result.Removed);
        Assert.Equal("provider_error", result.Status);
        Assert.Equal(original, File.ReadAllText(authFile.FilePath));
        Assert.Contains("Shared Codex-managed", result.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        AssertSafeDisconnectResult(result, authFile.FilePath, "synthetic-target-access-token");
    }

    [Fact]
    public async Task DisconnectAsyncRefusesSharedOpenAiCodexProviderEntry()
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write("""
        {
          "providers": {
            "openai-codex": {
              "type": "oauth",
              "access": "synthetic-shared-access-token",
              "refresh": "synthetic-shared-refresh-token",
              "expires": 4102444800000
            },
            "another-provider": {
              "custom": "preserve-provider-field"
            }
          }
        }
        """);
        var original = File.ReadAllText(authFile.FilePath);
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath, options =>
        {
            options.SubscriptionAuthFileProviderKey = "openai-codex";
        });

        var result = await service.DisconnectAsync(confirmed: true, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.False(result.Removed);
        Assert.Equal("provider_error", result.Status);
        Assert.Equal(original, File.ReadAllText(authFile.FilePath));
        Assert.Contains("Shared Codex-managed", result.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        AssertSafeDisconnectResult(
            result,
            authFile.FilePath,
            "synthetic-shared-access-token",
            "synthetic-shared-refresh-token");
    }

    [Fact]
    public async Task DisconnectAsyncRefusesNonSubscriptionEntryAtConfiguredKey()
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write("""
        {
          "metadata": { "label": "preserve-this" },
          "providers": {
            "chatgpt": {
              "provider": "ChatGPT",
              "auth_type": "api_key",
              "api_key": "synthetic-shared-api-key"
            }
          }
        }
        """);
        var original = File.ReadAllText(authFile.FilePath);
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath);

        Assert.False(service.CanDisconnectDedicatedCredential());
        var result = await service.DisconnectAsync(confirmed: true, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.False(result.Removed);
        Assert.Equal("unsupported_subscription_oauth", result.Status);
        Assert.Equal(original, File.ReadAllText(authFile.FilePath));
        AssertSafeDisconnectResult(result, authFile.FilePath, "synthetic-shared-api-key");
    }

    [Fact]
    public async Task MissingDedicatedCredentialIsNotDisconnectableAndDisconnectIsIdempotent()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath);

        Assert.False(service.CanDisconnectDedicatedCredential());
        var result = await service.DisconnectAsync(confirmed: true, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.False(result.Removed);
        Assert.Equal("not_connected", result.Status);
        Assert.False(File.Exists(authFile.FilePath));
        AssertSafeDisconnectResult(result, authFile.FilePath);
    }

    [Fact]
    public void InvalidCredentialJsonFailsClosedWithoutExposingContent()
    {
        using var authFile = SyntheticAuthFile.Create();
        authFile.Write("{ invalid-json: synthetic-private-placeholder }");
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath);

        Assert.False(service.CanDisconnectDedicatedCredential());
    }

    private static string DedicatedCredentialJson()
    {
        return """
        {
          "schema_version": 7,
          "metadata": {
            "label": "preserve-this"
          },
          "providers": {
            "chatgpt": {
              "provider": "ChatGPT",
              "auth_type": "subscription_oauth",
              "token_type": "Bearer",
              "access_token": "synthetic-target-access-token",
              "refresh_token": "synthetic-target-refresh-token",
              "expires_at": "2030-01-01T00:00:00Z",
              "audience": "https://api.openai.com/v1",
              "scope": "model.request"
            },
            "another-provider": {
              "provider": "SyntheticProvider",
              "access_token": "synthetic-preserved-access-token",
              "custom": "preserve-provider-field"
            }
          }
        }
        """;
    }

    private static string SubscriptionCredentialJson(
        string issuer,
        string tokenEndpoint,
        DateTimeOffset expiresAt)
    {
        return $$"""
        {
          "providers": {
            "chatgpt": {
              "provider": "ChatGPT",
              "auth_type": "subscription_oauth",
              "token_type": "Bearer",
              "access_token": "synthetic-advanced-access-token",
              "refresh_token": "synthetic-advanced-refresh-token",
              "expires_at": "{{expiresAt:O}}",
              "audience": "https://api.openai.com/v1",
              "issuer": "{{issuer}}",
              "scope": "model.request",
              "token_endpoint": "{{tokenEndpoint}}",
              "entitlement_status": "available"
            }
          }
        }
        """;
    }

    private static string TopLevelSubscriptionCredentialJson(DateTimeOffset expiresAt)
    {
        return $$"""
        {
          "schema_version": 7,
          "chatgpt": {
            "provider": "ChatGPT",
            "auth_type": "subscription_oauth",
            "token_type": "Bearer",
            "access_token": "synthetic-expiring-top-level-access-token",
            "refresh_token": "synthetic-expiring-top-level-refresh-token",
            "expires_at": "{{expiresAt:O}}",
            "audience": "https://api.openai.com/v1",
            "issuer": "https://auth.openai.com/",
            "scope": "model.request",
            "token_endpoint": "https://auth.openai.com/oauth/token",
            "entitlement_status": "available",
            "custom": "preserve-top-level-entry"
          }
        }
        """;
    }

    private static void DeleteDirectoryLink(string linkPath)
    {
        try
        {
            Directory.Delete(linkPath);
        }
        catch (DirectoryNotFoundException)
        {
            File.Delete(linkPath);
        }
    }

    private static void AssertSafeDisconnectResult(
        SocAgentSubscriptionOAuthDisconnectResult result,
        string authFilePath,
        params string[] syntheticSecrets)
    {
        var output = result.ToString();
        Assert.DoesNotContain(authFilePath, output, StringComparison.OrdinalIgnoreCase);
        foreach (var syntheticSecret in syntheticSecrets)
        {
            Assert.DoesNotContain(syntheticSecret, output, StringComparison.Ordinal);
        }
    }

    private static SocAgentSubscriptionOAuthConnectService CreateService(
        HttpClient httpClient,
        string authFilePath,
        Action<SocAgentOptions>? configure = null)
    {
        return CreateService(httpClient, authFilePath, new EphemeralDataProtectionProvider(), configure);
    }

    private static SocAgentSubscriptionOAuthConnectService CreateService(
        HttpClient httpClient,
        string authFilePath,
        IDataProtectionProvider protector,
        Action<SocAgentOptions>? configure = null,
        ISocAgentOAuthOperatorSessionValidator? sessionValidator = null)
    {
        var options = new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionConnectEnabled = true,
            SubscriptionAuthFilePath = authFilePath,
            SubscriptionAuthFileProviderKey = "chatgpt",
            SubscriptionClientId = "synthetic-client-id",
            SubscriptionClientSecret = "synthetic-client-secret",
            SubscriptionAuthorizationUrl = "https://auth.openai.com/oauth/authorize",
            SubscriptionTokenEndpoint = "https://auth.openai.com/oauth/token",
            SubscriptionRequiredScopes = "model.request"
        };
        configure?.Invoke(options);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        return new SocAgentSubscriptionOAuthConnectService(
            httpClient,
            Options.Create(options),
            configuration,
            protector,
            sessionValidator ?? new FakeOperatorSessionValidator(token =>
                string.Equals(token, AdminSessionToken, StringComparison.Ordinal)
                    ? CreateOperatorSession(AdminOperatorId, OperatorRoles.Admin)
                    : null),
            NullLogger<SocAgentSubscriptionOAuthConnectService>.Instance);
    }

    private static SocAgentModel CreatePageModel(
        SocAgentSubscriptionOAuthConnectService connectService,
        DefaultHttpContext context)
    {
        return new SocAgentModel(
            null!,
            connectService,
            null!,
            null!,
            NullLogger<SocAgentModel>.Instance)
        {
            PageContext = new PageContext { HttpContext = context }
        };
    }

    private static DefaultHttpContext CreateContext(
        string target = "/soc-agent",
        string role = OperatorRoles.Admin,
        Guid? operatorId = null,
        string? sessionToken = AdminSessionToken)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("127.0.0.1:5081");
        var parts = target.Split('?', 2);
        context.Request.Path = parts[0];
        if (parts.Length == 2)
        {
            context.Request.QueryString = new QueryString("?" + parts[1]);
        }

        context.Response.Body = new MemoryStream();
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, "synthetic-operator"),
            new(ClaimTypes.Role, role),
            new(OperatorAuthentication.OperatorIdClaim, (operatorId ?? AdminOperatorId).ToString())
        };
        if (!string.IsNullOrWhiteSpace(sessionToken))
        {
            claims.Add(new Claim(OperatorAuthentication.SessionTokenClaim, sessionToken));
        }

        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "SyntheticCookie"));
        return context;
    }

    private static string ExtractCookieHeader(string setCookie)
    {
        return setCookie.Split(';', 2)[0];
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(responseFactory(request));
        }
    }

    private sealed class FakeOperatorSessionValidator(Func<string, OperatorSession?> validate)
        : ISocAgentOAuthOperatorSessionValidator
    {
        public Task<OperatorSession?> ValidateAsync(string sessionToken, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(validate(sessionToken));
        }
    }

    private static OperatorSession CreateOperatorSession(Guid operatorId, string role)
    {
        var identity = new OperatorIdentity(
            operatorId,
            "synthetic-admin",
            "Synthetic Admin",
            role,
            Enabled: true,
            FailedLoginCount: 0,
            LockedUntil: null,
            PasswordHash: "synthetic-password-hash",
            ApiTokenHash: null,
            CredentialsChangedAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        return new OperatorSession(Guid.Parse("33333333-3333-3333-3333-333333333333"), identity, DateTimeOffset.UtcNow.AddHours(1));
    }

    private sealed class SyntheticAuthFile : IDisposable
    {
        private readonly string directory;

        private SyntheticAuthFile(string directory, string filePath)
        {
            this.directory = directory;
            FilePath = filePath;
        }

        public string FilePath { get; }

        public string DirectoryPath => directory;

        public static SyntheticAuthFile Create()
        {
            var directory = Path.Combine(Path.GetTempPath(), "challenger-siem-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            return new SyntheticAuthFile(directory, Path.Combine(directory, "auth.json"));
        }

        public void Write(string content)
        {
            File.WriteAllText(FilePath, content);
        }

        public void Dispose()
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
