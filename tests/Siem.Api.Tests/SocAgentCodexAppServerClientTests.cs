using System.Runtime.Versioning;
using System.Text.Json;
using Challenger.Siem.Api.SocAgent;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class SocAgentCodexAppServerClientTests
{
    [Fact]
    public async Task StartUsesIsolatedStateAndPublishesLoginRequiredWithoutCredentials()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        await using var client = fixture.CreateClient();

        await client.StartAsync(CancellationToken.None);

        var account = client.GetAccountStatus();
        Assert.True(account.IsAvailable);
        Assert.False(account.IsConnected);
        Assert.Equal("login_required", account.State);
        Assert.Null(account.PlanType);
        Assert.True(Directory.Exists(fixture.StateDirectory));
        Assert.True(Directory.Exists(Path.Combine(fixture.StateDirectory, "os-home")));
        Assert.False(File.Exists(Path.Combine(fixture.StateDirectory, "auth.json")));
    }

    [Fact]
    public async Task DeviceLoginPublishesOnlyAllowlistedValuesAndCanBeCancelled()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        await using var client = fixture.CreateClient();
        await client.StartAsync(CancellationToken.None);

        var started = await client.StartDeviceLoginAsync(CancellationToken.None);

        Assert.True(started.Started);
        Assert.True(started.Status.IsActive);
        Assert.Equal("waiting_for_user", started.Status.State);
        Assert.Equal("https://auth.openai.com/codex/device", started.Status.VerificationUrl);
        Assert.Equal("ABCD-EFGH", started.Status.UserCode);

        var cancelled = await client.CancelDeviceLoginAsync(CancellationToken.None);

        Assert.True(cancelled.Cancelled);
        Assert.False(cancelled.Status.IsActive);
        Assert.Equal("cancelled", cancelled.Status.State);
        Assert.Null(cancelled.Status.VerificationUrl);
        Assert.Null(cancelled.Status.UserCode);
        Assert.True(File.Exists(Path.Combine(fixture.StateDirectory, "cancel-observed")));
    }

    [Fact]
    public async Task DeviceLoginRejectsAnUntrustedVerificationUrlWithoutPublishingIt()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        File.WriteAllText(Path.Combine(fixture.StateDirectory, "unsafe-device-response"), string.Empty);
        await using var client = fixture.CreateClient();
        await client.StartAsync(CancellationToken.None);

        var started = await client.StartDeviceLoginAsync(CancellationToken.None);

        Assert.False(started.Started);
        Assert.False(started.Status.IsActive);
        Assert.Equal("failed", started.Status.State);
        Assert.Null(started.Status.VerificationUrl);
        Assert.Null(started.Status.UserCode);
    }

    [Fact]
    public async Task CompletedLoginIsVerifiedByAccountReadBeforePublishingConnected()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        File.WriteAllText(Path.Combine(fixture.StateDirectory, "complete-login"), string.Empty);
        await using var client = fixture.CreateClient();
        await client.StartAsync(CancellationToken.None);

        var started = await client.StartDeviceLoginAsync(CancellationToken.None);
        await WaitUntilAsync(() => client.GetAccountStatus().IsConnected, TimeSpan.FromSeconds(3));

        Assert.True(started.Started);
        Assert.Equal("connected", client.GetAccountStatus().State);
        Assert.Equal("ready", client.GetLoginStatus().State);
        Assert.False(client.GetLoginStatus().IsActive);
        Assert.Null(client.GetLoginStatus().VerificationUrl);
        Assert.True(File.Exists(Path.Combine(fixture.StateDirectory, "verification-read-observed")));
    }

    [Fact]
    public async Task IdLessLoginCompletionFaultsTransportRatherThanCrossingAttempts()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        File.WriteAllText(Path.Combine(fixture.StateDirectory, "idless-login-completion"), string.Empty);
        await using var client = fixture.CreateClient();
        await client.StartAsync(CancellationToken.None);

        await client.StartDeviceLoginAsync(CancellationToken.None);
        await WaitUntilAsync(() => !client.GetAccountStatus().IsAvailable, TimeSpan.FromSeconds(3));

        Assert.Equal("unavailable", client.GetAccountStatus().State);
        Assert.False(client.GetLoginStatus().IsActive);
        Assert.Null(client.GetLoginStatus().VerificationUrl);
        Assert.Null(client.GetLoginStatus().UserCode);
    }

    [Fact]
    public async Task CredentialBrokerRefreshesAccountThenReadsBoundedPrivateAuthFile()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        fixture.WritePrivateCredentialFile();
        await using var client = fixture.CreateClient();
        await client.StartAsync(CancellationToken.None);

        var account = client.GetAccountStatus();
        Assert.True(account.IsConnected);
        Assert.Equal("connected", account.State);
        Assert.Equal("plus", account.PlanType);

        var credential = await ((ISocAgentCodexCredentialBroker)client)
            .GetCredentialAsync(CancellationToken.None);

        Assert.Equal(48, credential.AccessToken.Length);
        Assert.Equal(22, credential.AccountId?.Length);
        Assert.True(File.Exists(Path.Combine(fixture.StateDirectory, "refresh-observed")));
    }

    [Fact]
    public async Task CredentialBrokerRejectsAnOversizedAuthFileWithOnlyASafeError()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        var credentialPath = Path.Combine(fixture.StateDirectory, "auth.json");
        await using (var stream = new FileStream(credentialPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.SetLength((1024 * 1024) + 1);
        }

        File.SetUnixFileMode(
            credentialPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite);
        await using var client = fixture.CreateClient();
        await client.StartAsync(CancellationToken.None);

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            ((ISocAgentCodexCredentialBroker)client).GetCredentialAsync(CancellationToken.None));

        Assert.Equal("auth_failed", exception.ErrorCode);
        Assert.DoesNotContain(credentialPath, exception.OperatorSafeMessage, StringComparison.Ordinal);
        Assert.Contains("unavailable or unsafe", exception.OperatorSafeMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(".codex")]
    [InlineData(".pi")]
    public async Task StateBelowGlobalAgentStoresFailsClosedWithoutCreatingTarget(string protectedDirectory)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(userProfile))
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        var forbiddenTarget = Path.Combine(
            userProfile,
            protectedDirectory,
            $"challenger-siem-test-{Guid.NewGuid():N}");
        Assert.False(Directory.Exists(forbiddenTarget));
        await using var client = fixture.CreateClient(forbiddenTarget);

        await client.StartAsync(CancellationToken.None);

        var account = client.GetAccountStatus();
        Assert.False(account.IsAvailable);
        Assert.False(account.IsConnected);
        Assert.Equal("unavailable", account.State);
        Assert.False(Directory.Exists(forbiddenTarget));
    }

    [Fact]
    public async Task RelativeStateTraversalFailsClosedOutsideProjectLocalDirectory()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        var escapedTarget = Path.Combine(fixture.RootDirectory, "escaped-state");
        await using var client = fixture.CreateClient(Path.Combine(".local", "..", "escaped-state"));

        await client.StartAsync(CancellationToken.None);

        Assert.Equal("unavailable", client.GetAccountStatus().State);
        Assert.False(Directory.Exists(escapedTarget));
    }

    [Fact]
    public async Task LinkedStateAncestorFailsClosedWithoutWritingThroughLink()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = CodexAppServerFixture.Create();
        var actualParent = Path.Combine(fixture.RootDirectory, "actual-state-parent");
        var linkedParent = Path.Combine(fixture.RootDirectory, "linked-state-parent");
        Directory.CreateDirectory(actualParent);
        Directory.CreateSymbolicLink(linkedParent, actualParent);
        var linkedTarget = Path.Combine(linkedParent, "isolated-state");
        await using var client = fixture.CreateClient(linkedTarget);

        await client.StartAsync(CancellationToken.None);

        Assert.Equal("unavailable", client.GetAccountStatus().State);
        Assert.False(Directory.Exists(Path.Combine(actualParent, "isolated-state")));
    }

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow.Add(timeout);
        while (!condition() && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(25);
        }

        Assert.True(condition(), "The synthetic app-server state did not reach the expected condition before the bounded timeout.");
    }

    private sealed class CodexAppServerFixture : IDisposable
    {
        private const string FakeAppServer = """
            #!/usr/bin/python3
            import json
            import os
            import pathlib
            import sys

            codex_home = pathlib.Path(os.environ["CODEX_HOME"])
            auth_file = codex_home / "auth.json"

            for raw_line in sys.stdin:
                message = json.loads(raw_line)
                request_id = message.get("id")
                if request_id is None:
                    continue

                method = message.get("method")
                parameters = message.get("params") or {}
                if method == "initialize":
                    result = {"codexHome": str(codex_home)}
                elif method == "account/read":
                    if parameters.get("refreshToken") is True:
                        (codex_home / "refresh-observed").touch()
                    elif auth_file.is_file():
                        (codex_home / "verification-read-observed").touch()
                    account = None
                    if auth_file.is_file():
                        account = {"type": "chatgpt", "planType": "plus"}
                    result = {"requiresOpenaiAuth": True, "account": account}
                elif method == "account/login/start":
                    verification_url = "https://auth.openai.com/codex/device"
                    if (codex_home / "unsafe-device-response").exists():
                        verification_url = "https://example.invalid/codex/device"
                    result = {
                        "type": "chatgptDeviceCode",
                        "loginId": "synthetic-login-id",
                        "verificationUrl": verification_url,
                        "userCode": "ABCD-EFGH"
                    }
                elif method == "account/login/cancel":
                    (codex_home / "cancel-observed").touch()
                    result = {"status": "canceled"}
                else:
                    print(json.dumps({
                        "id": request_id,
                        "error": {"code": -32601, "message": "unsupported synthetic method"}
                    }), flush=True)
                    continue

                print(json.dumps({"id": request_id, "result": result}), flush=True)
                if method == "account/login/start" and (codex_home / "complete-login").exists():
                    auth_file.write_text(json.dumps({
                        "auth_mode": "chatgpt",
                        "tokens": {
                            "access_token": "t" * 48,
                            "account_id": "a" * 22
                        }
                    }))
                    auth_file.chmod(0o600)
                    print(json.dumps({
                        "method": "account/login/completed",
                        "params": {"loginId": "synthetic-login-id", "success": True}
                    }), flush=True)
                elif method == "account/login/start" and (codex_home / "idless-login-completion").exists():
                    print(json.dumps({
                        "method": "account/login/completed",
                        "params": {"success": True}
                    }), flush=True)
            """;

        private CodexAppServerFixture(string rootDirectory, string executablePath)
        {
            RootDirectory = rootDirectory;
            ExecutablePath = executablePath;
            StateDirectory = Path.Combine(rootDirectory, "state");
            WorkingDirectory = Path.Combine(rootDirectory, "work");
        }

        public string RootDirectory { get; }

        public string ExecutablePath { get; }

        public string StateDirectory { get; }

        public string WorkingDirectory { get; }

        [SupportedOSPlatform("linux")]
        public static CodexAppServerFixture Create()
        {
            var rootDirectory = Path.Combine(
                Path.GetTempPath(),
                $"challenger-siem-codex-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(rootDirectory);
            File.SetUnixFileMode(
                rootDirectory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var executablePath = Path.Combine(rootDirectory, "fake-codex");
            File.WriteAllText(executablePath, FakeAppServer);
            File.SetUnixFileMode(
                executablePath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.CreateDirectory(Path.Combine(rootDirectory, "state"));
            File.SetUnixFileMode(
                Path.Combine(rootDirectory, "state"),
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            return new CodexAppServerFixture(rootDirectory, executablePath);
        }

        public SocAgentCodexAppServerClient CreateClient(string? stateDirectory = null)
        {
            var options = new SocAgentCodexAppServerOptions
            {
                Enabled = true,
                ExecutablePath = ExecutablePath,
                StateDirectory = stateDirectory ?? StateDirectory,
                WorkingDirectory = WorkingDirectory,
                StartupTimeoutSeconds = 5,
                RequestTimeoutSeconds = 5,
                LoginTimeoutSeconds = 60,
                MaxJsonLineBytes = 64 * 1024
            };
            return new SocAgentCodexAppServerClient(
                Options.Create(options),
                new TestHostEnvironment(RootDirectory),
                TimeProvider.System,
                NullLogger<SocAgentCodexAppServerClient>.Instance);
        }

        [SupportedOSPlatform("linux")]
        public void WritePrivateCredentialFile()
        {
            var payload = JsonSerializer.Serialize(new
            {
                auth_mode = "chatgpt",
                tokens = new
                {
                    access_token = new string('t', 48),
                    account_id = new string('a', 22)
                }
            });
            var credentialPath = Path.Combine(StateDirectory, "auth.json");
            File.WriteAllText(credentialPath, payload);
            File.SetUnixFileMode(
                credentialPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        public void Dispose()
        {
            Directory.Delete(RootDirectory, recursive: true);
        }
    }

    private sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;

        public string ApplicationName { get; set; } = "Challenger.Siem.Api.Tests";

        public string ContentRootPath { get; set; } = contentRootPath;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
