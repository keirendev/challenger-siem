using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.SocAgent;

public sealed class SocAgentCodexAppServerClient :
    ISocAgentCodexAppServerClient,
    ISocAgentCodexCredentialBroker,
    IHostedService,
    IAsyncDisposable
{
    private const int MaxCredentialFileBytes = 1024 * 1024;
    private const int MaxStandardErrorBytes = 256 * 1024;
    private const string DeviceVerificationUrl = "https://auth.openai.com/codex/device";

    private static readonly byte[] NewLine = [(byte)'\n'];
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonDocumentOptions JsonDocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 32
    };
    private static readonly Regex DeviceCodePattern = new(
        "^[A-Z0-9](?:[A-Z0-9-]{2,30}[A-Z0-9])$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly HashSet<string> KnownPlanTypes = new(StringComparer.Ordinal)
    {
        "free",
        "go",
        "plus",
        "pro",
        "prolite",
        "team",
        "self_serve_business_usage_based",
        "business",
        "enterprise_cbp_usage_based",
        "enterprise",
        "edu",
        "unknown"
    };

    private readonly SocAgentCodexAppServerOptions options;
    private readonly IHostEnvironment hostEnvironment;
    private readonly TimeProvider timeProvider;
    private readonly ILogger<SocAgentCodexAppServerClient> logger;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement>> pendingRequests = new();
    private readonly SemaphoreSlim startGate = new(1, 1);
    private readonly SemaphoreSlim writeGate = new(1, 1);
    private readonly SemaphoreSlim loginGate = new(1, 1);
    private readonly SemaphoreSlim credentialGate = new(1, 1);
    private readonly object processGate = new();
    private readonly object statusGate = new();
    private readonly CancellationTokenSource lifetimeCancellation = new();

    private Process? process;
    private CancellationTokenSource? processCancellation;
    private Task? stdoutPump;
    private Task? stderrPump;
    private Task? processMonitor;
    private long processGeneration;
    private long nextRequestId;
    private bool connectionReady;
    private bool stopping;
    private bool disposed;
    private string? codexHome;
    private string? sessionWorkingDirectory;

    private bool loginAttemptReserved;
    private string? activeLoginId;
    private CancellationTokenSource? loginTimeoutCancellation;
    private LoginCompletionNotice? earlyLoginCompletion;

    private SocAgentCodexAccountStatus accountStatus = new(
        false,
        false,
        "unavailable",
        null,
        "The SIEM-managed ChatGPT login service is unavailable.");

    private SocAgentCodexLoginStatus loginStatus = new(
        false,
        false,
        "unavailable",
        null,
        null,
        "The SIEM-managed ChatGPT login service is unavailable.");

    public SocAgentCodexAppServerClient(
        IOptions<SocAgentCodexAppServerOptions> options,
        IHostEnvironment hostEnvironment,
        TimeProvider timeProvider,
        ILogger<SocAgentCodexAppServerClient> logger)
    {
        this.options = options.Value;
        this.hostEnvironment = hostEnvironment;
        this.timeProvider = timeProvider;
        this.logger = logger;
    }

    public SocAgentCodexAccountStatus GetAccountStatus()
    {
        lock (statusGate)
        {
            return accountStatus;
        }
    }

    public SocAgentCodexLoginStatus GetLoginStatus()
    {
        lock (statusGate)
        {
            return loginStatus;
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!options.Enabled)
        {
            SetDisabledStatus();
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            SetUnsupportedPlatformStatus();
            return;
        }

        try
        {
            await EnsureStartedAsync(cancellationToken);
            await ReadAccountStatusAsync(refreshToken: false, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            SetUnavailableStatus("The SIEM-managed ChatGPT login service could not be started.");
            LogSafeFailure("start", ex);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Process? currentProcess;
        CancellationTokenSource? currentProcessCancellation;
        string? currentSessionWorkingDirectory;
        Task[] backgroundTasks;

        lock (processGate)
        {
            if (stopping)
            {
                return;
            }

            stopping = true;
            connectionReady = false;
            currentProcess = process;
            currentProcessCancellation = processCancellation;
            currentSessionWorkingDirectory = sessionWorkingDirectory;
            backgroundTasks = new Task?[] { stdoutPump, stderrPump, processMonitor }
                .Where(task => task is not null)
                .Cast<Task>()
                .ToArray();
        }

        lifetimeCancellation.Cancel();
        CancelLoginTimeout();
        FailAllPendingRequests(new CodexAppServerProtocolException("The Codex app-server is stopping."));

        if (currentProcess is not null)
        {
            try
            {
                await writeGate.WaitAsync(cancellationToken);
                try
                {
                    currentProcess.StandardInput.Close();
                }
                finally
                {
                    writeGate.Release();
                }

                var shutdownTimeout = TimeSpan.FromSeconds(Math.Clamp(options.StartupTimeoutSeconds, 2, 15));
                await currentProcess.WaitForExitAsync(CancellationToken.None).WaitAsync(shutdownTimeout, cancellationToken);
            }
            catch (Exception ex) when (ex is OperationCanceledException or TimeoutException or InvalidOperationException)
            {
                TryKill(currentProcess);
            }
        }

        currentProcessCancellation?.Cancel();
        if (backgroundTasks.Length > 0)
        {
            try
            {
                await Task.WhenAll(backgroundTasks).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
            }
            catch (Exception ex) when (ex is OperationCanceledException or TimeoutException)
            {
                // The child is already stopped or killed; transport pumps are best-effort during shutdown.
            }
        }

        lock (processGate)
        {
            process = null;
            processCancellation = null;
            stdoutPump = null;
            stderrPump = null;
            processMonitor = null;
            codexHome = null;
            sessionWorkingDirectory = null;
        }

        currentProcessCancellation?.Dispose();
        currentProcess?.Dispose();
        CleanupEmptySessionWorkingDirectory(currentSessionWorkingDirectory);

        lock (statusGate)
        {
            loginAttemptReserved = false;
            activeLoginId = null;
            earlyLoginCompletion = null;
            accountStatus = new(
                false,
                false,
                "stopped",
                null,
                "The SIEM-managed ChatGPT login service is stopped.");
            loginStatus = new(
                false,
                false,
                "stopped",
                null,
                null,
                "The SIEM-managed ChatGPT login service is stopped.");
        }
    }

    public async Task<SocAgentCodexLoginStartResult> StartDeviceLoginAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!options.Enabled)
        {
            SetDisabledStatus();
            return new SocAgentCodexLoginStartResult(false, GetLoginStatus());
        }

        if (OperatingSystem.IsWindows())
        {
            SetUnsupportedPlatformStatus();
            return new SocAgentCodexLoginStartResult(false, GetLoginStatus());
        }

        await loginGate.WaitAsync(cancellationToken);
        try
        {
            lock (statusGate)
            {
                if (loginAttemptReserved)
                {
                    return new SocAgentCodexLoginStartResult(
                        false,
                        loginStatus with
                        {
                            OperatorMessage = "A ChatGPT login is already active. Complete or cancel it before starting another."
                        });
                }
            }

            try
            {
                await EnsureStartedAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                SetUnavailableStatus("The SIEM-managed ChatGPT login service could not start a login.");
                LogSafeFailure("login start", ex);
                return new SocAgentCodexLoginStartResult(false, GetLoginStatus());
            }

            lock (statusGate)
            {
                loginAttemptReserved = true;
                activeLoginId = null;
                earlyLoginCompletion = null;
                loginStatus = new(
                    true,
                    true,
                    "starting",
                    null,
                    null,
                    "Starting the ChatGPT device login.");
            }

            JsonElement result;
            var loginTransportGeneration = CaptureTransportGeneration(requireReadyConnection: true);
            try
            {
                result = await SendRequestAsync(
                    "account/login/start",
                    new Dictionary<string, object?>
                    {
                        ["type"] = "chatgptDeviceCode"
                    },
                    RequestTimeout,
                    cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                FaultTransport(loginTransportGeneration, "The Codex app-server login request was interrupted.");
                throw;
            }
            catch (Exception ex)
            {
                FaultTransport(loginTransportGeneration, "The Codex app-server login request failed ambiguously.");
                LogSafeFailure("login request", ex);
                return new SocAgentCodexLoginStartResult(false, GetLoginStatus());
            }

            string loginId;
            string verificationUrl;
            string userCode;
            try
            {
                var type = ReadRequiredString(result, "type", 64);
                if (!string.Equals(type, "chatgptDeviceCode", StringComparison.Ordinal))
                {
                    throw new CodexAppServerProtocolException("The Codex app-server returned an unexpected login type.");
                }

                loginId = ReadRequiredString(result, "loginId", 256);
                verificationUrl = ReadRequiredString(result, "verificationUrl", 256);
                userCode = ReadRequiredString(result, "userCode", 32);
                ValidateDeviceLoginValues(verificationUrl, userCode);
            }
            catch (Exception ex) when (ex is CodexAppServerProtocolException or UriFormatException)
            {
                FaultTransport(loginTransportGeneration, "The Codex app-server login response was invalid.");
                LogSafeFailure("login validation", ex);
                return new SocAgentCodexLoginStartResult(false, GetLoginStatus());
            }

            CancellationTokenSource? timeoutCancellation = null;
            var verifyCompletedLogin = false;
            var loginStillReserved = true;
            SocAgentCodexLoginStatus publishedStatus;
            lock (statusGate)
            {
                if (!loginAttemptReserved)
                {
                    loginStillReserved = false;
                }
                else
                {
                    activeLoginId = loginId;
                    if (earlyLoginCompletion is { } early
                        && string.Equals(early.LoginId, loginId, StringComparison.Ordinal))
                    {
                        verifyCompletedLogin = ApplyLoginCompletionLocked(early.Success);
                    }
                    else
                    {
                        earlyLoginCompletion = null;
                        timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetimeCancellation.Token);
                        loginTimeoutCancellation = timeoutCancellation;
                        loginStatus = new(
                            true,
                            true,
                            "waiting_for_user",
                            verificationUrl,
                            userCode,
                            "Open the verification page, sign in to ChatGPT, and enter the one-time code.");
                    }
                }

                publishedStatus = loginStatus;
            }

            if (!loginStillReserved)
            {
                return new SocAgentCodexLoginStartResult(false, publishedStatus);
            }

            if (timeoutCancellation is not null)
            {
                _ = WatchLoginTimeoutAsync(loginId, timeoutCancellation);
            }
            else if (verifyCompletedLogin)
            {
                _ = VerifyCompletedLoginAsync();
            }

            return new SocAgentCodexLoginStartResult(true, publishedStatus);
        }
        finally
        {
            loginGate.Release();
        }
    }

    public async Task<SocAgentCodexLoginCancelResult> CancelDeviceLoginAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await loginGate.WaitAsync(cancellationToken);
        try
        {
            string? loginId;
            lock (statusGate)
            {
                loginId = activeLoginId;
                if (!loginAttemptReserved || string.IsNullOrWhiteSpace(loginId))
                {
                    return new SocAgentCodexLoginCancelResult(
                        false,
                        loginStatus with
                        {
                            OperatorMessage = "There is no active ChatGPT login to cancel."
                        });
                }

                loginStatus = loginStatus with
                {
                    State = "cancelling",
                    OperatorMessage = "Cancelling the ChatGPT login."
                };
            }

            JsonElement result;
            try
            {
                result = await SendRequestAsync(
                    "account/login/cancel",
                    new Dictionary<string, object?>
                    {
                        ["loginId"] = loginId
                    },
                    RequestTimeout,
                    cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                RestoreWaitingLoginStatus();
                throw;
            }
            catch (Exception ex)
            {
                RestoreWaitingLoginStatus();
                LogSafeFailure("login cancellation", ex);
                return new SocAgentCodexLoginCancelResult(false, GetLoginStatus());
            }

            string cancelStatus;
            try
            {
                cancelStatus = ReadRequiredString(result, "status", 32);
            }
            catch (CodexAppServerProtocolException ex)
            {
                RestoreWaitingLoginStatus();
                LogSafeFailure("login cancellation validation", ex);
                return new SocAgentCodexLoginCancelResult(false, GetLoginStatus());
            }

            var cancelled = string.Equals(cancelStatus, "canceled", StringComparison.Ordinal);
            if (!cancelled && !string.Equals(cancelStatus, "notFound", StringComparison.Ordinal))
            {
                RestoreWaitingLoginStatus();
                return new SocAgentCodexLoginCancelResult(false, GetLoginStatus());
            }

            SocAgentCodexLoginStatus terminalStatus;
            lock (statusGate)
            {
                if (loginAttemptReserved && string.Equals(activeLoginId, loginId, StringComparison.Ordinal))
                {
                    ClearLoginAttemptLocked();
                    loginStatus = new(
                        true,
                        false,
                        "cancelled",
                        null,
                        null,
                        cancelled
                            ? "The ChatGPT login was cancelled."
                            : "The ChatGPT login was no longer active.");
                }

                terminalStatus = loginStatus;
            }

            return new SocAgentCodexLoginCancelResult(cancelled, terminalStatus);
        }
        finally
        {
            loginGate.Release();
        }
    }

    async Task<SocAgentCodexCredential> ISocAgentCodexCredentialBroker.GetCredentialAsync(
        CancellationToken cancellationToken)
    {
        await credentialGate.WaitAsync(cancellationToken);
        try
        {
            return await GetCredentialCoreAsync(cancellationToken);
        }
        finally
        {
            credentialGate.Release();
        }
    }

    private async Task<SocAgentCodexCredential> GetCredentialCoreAsync(
        CancellationToken cancellationToken)
    {
        if (!options.Enabled)
        {
            throw new SocAgentModelProviderException(
                "provider_not_configured",
                "The SIEM-managed ChatGPT login service is disabled.");
        }

        if (OperatingSystem.IsWindows())
        {
            throw new SocAgentModelProviderException(
                "provider_not_configured",
                "SIEM-managed ChatGPT login is not supported on a Windows SIEM server in this build because an owner-only credential ACL cannot yet be enforced.");
        }

        SocAgentCodexAccountStatus refreshed;
        try
        {
            await EnsureStartedAsync(cancellationToken);
            refreshed = await ReadAccountStatusAsync(refreshToken: true, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            SetUnavailableStatus("The SIEM-managed ChatGPT login could not be refreshed.");
            LogSafeFailure("credential refresh", ex);
            throw new SocAgentModelProviderException(
                "auth_failed",
                "The shared ChatGPT login could not be refreshed. Ask an administrator to log in again.");
        }

        if (!refreshed.IsConnected)
        {
            throw new SocAgentModelProviderException(
                "auth_required",
                "ChatGPT login is required. Ask an administrator to complete the shared server login.");
        }

        string? currentCodexHome;
        lock (processGate)
        {
            currentCodexHome = codexHome;
        }

        if (string.IsNullOrWhiteSpace(currentCodexHome))
        {
            throw new SocAgentModelProviderException(
                "auth_failed",
                "The SIEM-managed ChatGPT credential store is unavailable. Ask an administrator to log in again.");
        }

        try
        {
            return await ReadCredentialFileAsync(currentCodexHome, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogSafeFailure("credential read", ex);
            throw new SocAgentModelProviderException(
                "auth_failed",
                "The SIEM-managed ChatGPT credential is unavailable or unsafe. Ask an administrator to log in again.");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
        {
            return;
        }

        await StopAsync(CancellationToken.None);
        disposed = true;
        lifetimeCancellation.Dispose();
        GC.SuppressFinalize(this);
    }

    private TimeSpan StartupTimeout =>
        TimeSpan.FromSeconds(Math.Clamp(options.StartupTimeoutSeconds, 5, 60));

    private TimeSpan RequestTimeout =>
        TimeSpan.FromSeconds(Math.Clamp(options.RequestTimeoutSeconds, 5, 120));

    private TimeSpan LoginTimeout =>
        TimeSpan.FromSeconds(Math.Clamp(options.LoginTimeoutSeconds, 60, 1800));

    private int MaxJsonLineBytes =>
        Math.Clamp(options.MaxJsonLineBytes, 16 * 1024, 4 * 1024 * 1024);

    private async Task EnsureStartedAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (!options.Enabled)
        {
            throw new CodexAppServerProtocolException("The Codex app-server integration is disabled.");
        }

        if (OperatingSystem.IsWindows())
        {
            throw new CodexAppServerProtocolException("The Codex app-server integration requires an owner-only credential store that this build cannot enforce on Windows.");
        }

        if (IsConnectionReady())
        {
            return;
        }

        await startGate.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (stopping)
            {
                throw new CodexAppServerProtocolException("The Codex app-server integration is stopping.");
            }

            if (IsConnectionReady())
            {
                return;
            }

            ResetFailedProcess();
            var stateDirectory = ResolveConfiguredDirectory(options.StateDirectory, ".local/soc-agent/codex");
            var workingRoot = ResolveConfiguredDirectory(options.WorkingDirectory, ".local/soc-agent/codex/work");
            ValidateSafeDirectoryTarget(stateDirectory);
            ValidateSafeDirectoryTarget(workingRoot);
            EnsurePrivateDirectory(stateDirectory);
            EnsurePrivateDirectory(workingRoot);

            var syntheticHome = Path.Combine(stateDirectory, "os-home");
            var temporaryDirectory = Path.Combine(stateDirectory, "tmp");
            var currentWorkingDirectory = Path.Combine(workingRoot, $"session-{Guid.NewGuid():N}");
            EnsurePrivateDirectory(syntheticHome);
            EnsurePrivateDirectory(temporaryDirectory);
            EnsurePrivateDirectory(currentWorkingDirectory);

            var executable = ResolveCodexExecutable();
            var startInfo = CreateStartInfo(
                executable,
                stateDirectory,
                syntheticHome,
                temporaryDirectory,
                currentWorkingDirectory);
            var startedProcess = Process.Start(startInfo)
                ?? throw new CodexAppServerProtocolException("The Codex app-server process did not start.");
            var startedCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetimeCancellation.Token);
            var generation = Interlocked.Increment(ref processGeneration);
            var abortStart = false;

            lock (processGate)
            {
                if (stopping)
                {
                    abortStart = true;
                }
                else
                {
                    process = startedProcess;
                    processCancellation = startedCancellation;
                    codexHome = stateDirectory;
                    sessionWorkingDirectory = currentWorkingDirectory;
                    connectionReady = false;
                    stdoutPump = PumpStandardOutputAsync(startedProcess, generation, startedCancellation.Token);
                    stderrPump = PumpStandardErrorAsync(startedProcess, generation, startedCancellation.Token);
                    processMonitor = MonitorProcessAsync(startedProcess, generation, startedCancellation.Token);
                }
            }

            if (abortStart)
            {
                startedCancellation.Cancel();
                TryKill(startedProcess);
                startedCancellation.Dispose();
                startedProcess.Dispose();
                CleanupEmptySessionWorkingDirectory(currentWorkingDirectory);
                throw new CodexAppServerProtocolException("The Codex app-server integration is stopping.");
            }

            SetStartingStatus();
            try
            {
                var initializeResult = await SendRequestAsync(
                    "initialize",
                    new Dictionary<string, object?>
                    {
                        ["clientInfo"] = new Dictionary<string, object?>
                        {
                            ["name"] = "challenger_siem_soc_agent",
                            ["title"] = "Challenger SIEM soc-agent",
                            ["version"] = "1.0.0"
                        },
                        ["capabilities"] = new Dictionary<string, object?>
                        {
                            ["experimentalApi"] = false
                        }
                    },
                    StartupTimeout,
                    cancellationToken,
                    requireReadyConnection: false);
                ValidateInitializedCodexHome(initializeResult, stateDirectory);
                await SendNotificationAsync(
                    "initialized",
                    new Dictionary<string, object?>(),
                    cancellationToken,
                    requireReadyConnection: false);

                lock (processGate)
                {
                    if (generation != processGeneration || process != startedProcess || startedProcess.HasExited)
                    {
                        throw new CodexAppServerProtocolException("The Codex app-server exited during initialization.");
                    }

                    connectionReady = true;
                }

                SetAvailableStatus();
            }
            catch
            {
                FaultTransport(generation, "The Codex app-server initialization failed.");
                throw;
            }
        }
        finally
        {
            startGate.Release();
        }
    }

    private async Task<SocAgentCodexAccountStatus> ReadAccountStatusAsync(
        bool refreshToken,
        CancellationToken cancellationToken)
    {
        var result = await SendRequestAsync(
            "account/read",
            new Dictionary<string, object?>
            {
                ["refreshToken"] = refreshToken
            },
            RequestTimeout,
            cancellationToken);

        if (!result.TryGetProperty("requiresOpenaiAuth", out var requiresOpenAiAuth)
            || requiresOpenAiAuth.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new CodexAppServerProtocolException("The Codex app-server account response was invalid.");
        }

        SocAgentCodexAccountStatus status;
        if (!result.TryGetProperty("account", out var account)
            || account.ValueKind == JsonValueKind.Null)
        {
            status = new(
                true,
                false,
                "login_required",
                null,
                "ChatGPT login is required for soc-agent.");
        }
        else if (account.ValueKind == JsonValueKind.Object)
        {
            var accountType = ReadRequiredString(account, "type", 64);
            if (string.Equals(accountType, "chatgpt", StringComparison.Ordinal))
            {
                status = new(
                    true,
                    true,
                    "connected",
                    ReadSafePlanType(account),
                    "The shared ChatGPT subscription is connected.");
            }
            else
            {
                status = new(
                    true,
                    false,
                    "unsupported_account",
                    null,
                    "The isolated Codex credential store is not using ChatGPT subscription login.");
            }
        }
        else
        {
            throw new CodexAppServerProtocolException("The Codex app-server account response was invalid.");
        }

        PublishAccountStatus(status);
        return status;
    }

    private async Task<JsonElement> SendRequestAsync(
        string method,
        object parameters,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        bool requireReadyConnection = true)
    {
        var expectedGeneration = CaptureTransportGeneration(requireReadyConnection);
        var requestId = Interlocked.Increment(ref nextRequestId);
        var completion = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pendingRequests.TryAdd(requestId, completion))
        {
            throw new CodexAppServerProtocolException("A duplicate Codex app-server request identifier was generated.");
        }

        var message = new Dictionary<string, object?>
        {
            ["method"] = method,
            ["id"] = requestId,
            ["params"] = parameters
        };

        try
        {
            await WriteMessageAsync(
                message,
                cancellationToken,
                requireReadyConnection,
                expectedGeneration);
            var result = await completion.Task.WaitAsync(timeout, cancellationToken);
            if (!IsCurrentGeneration(expectedGeneration, requireReadyConnection))
            {
                throw new CodexAppServerProtocolException("The Codex app-server connection changed during a request.");
            }

            return result;
        }
        catch (TimeoutException ex)
        {
            throw new CodexAppServerProtocolException("The Codex app-server request timed out.", ex);
        }
        finally
        {
            pendingRequests.TryRemove(requestId, out _);
        }
    }

    private Task SendNotificationAsync(
        string method,
        object parameters,
        CancellationToken cancellationToken,
        bool requireReadyConnection = true)
    {
        var message = new Dictionary<string, object?>
        {
            ["method"] = method,
            ["params"] = parameters
        };
        return WriteMessageAsync(message, cancellationToken, requireReadyConnection);
    }

    private async Task WriteMessageAsync(
        object message,
        CancellationToken cancellationToken,
        bool requireReadyConnection,
        long? expectedGeneration = null)
    {
        Process currentProcess;
        long generation;
        lock (processGate)
        {
            if (process is null || process.HasExited || (requireReadyConnection && !connectionReady))
            {
                throw new CodexAppServerProtocolException("The Codex app-server transport is unavailable.");
            }

            currentProcess = process;
            generation = processGeneration;
            if (expectedGeneration.HasValue && generation != expectedGeneration.Value)
            {
                throw new CodexAppServerProtocolException("The Codex app-server transport changed before the request was sent.");
            }
        }

        byte[] serialized;
        try
        {
            serialized = JsonSerializer.SerializeToUtf8Bytes(message);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            throw new CodexAppServerProtocolException("A Codex app-server request could not be serialized.", ex);
        }

        if (serialized.Length > MaxJsonLineBytes)
        {
            throw new CodexAppServerProtocolException("A Codex app-server request exceeded the configured size limit.");
        }

        await writeGate.WaitAsync(cancellationToken);
        try
        {
            lock (processGate)
            {
                if (generation != processGeneration || process != currentProcess || currentProcess.HasExited)
                {
                    throw new CodexAppServerProtocolException("The Codex app-server transport changed before the request was sent.");
                }
            }

            await currentProcess.StandardInput.BaseStream.WriteAsync(serialized, cancellationToken);
            await currentProcess.StandardInput.BaseStream.WriteAsync(NewLine, cancellationToken);
            await currentProcess.StandardInput.BaseStream.FlushAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException)
        {
            FaultTransport(generation, "The Codex app-server input stream failed.");
            throw new CodexAppServerProtocolException("The Codex app-server request could not be sent.", ex);
        }
        finally
        {
            writeGate.Release();
        }
    }

    private async Task PumpStandardOutputAsync(
        Process currentProcess,
        long generation,
        CancellationToken cancellationToken)
    {
        var readBuffer = ArrayPool<byte>.Shared.Rent(8192);
        var lineBuffer = new ArrayBufferWriter<byte>();
        try
        {
            while (true)
            {
                var bytesRead = await currentProcess.StandardOutput.BaseStream.ReadAsync(
                    readBuffer.AsMemory(0, readBuffer.Length),
                    cancellationToken);
                if (bytesRead == 0)
                {
                    if (lineBuffer.WrittenCount != 0)
                    {
                        throw new CodexAppServerProtocolException("The Codex app-server ended with an incomplete JSON line.");
                    }

                    break;
                }

                var offset = 0;
                while (offset < bytesRead)
                {
                    var relativeNewLine = readBuffer.AsSpan(offset, bytesRead - offset).IndexOf((byte)'\n');
                    var segmentLength = relativeNewLine < 0 ? bytesRead - offset : relativeNewLine;
                    if (lineBuffer.WrittenCount + segmentLength > MaxJsonLineBytes)
                    {
                        throw new CodexAppServerProtocolException("A Codex app-server response exceeded the configured size limit.");
                    }

                    if (segmentLength > 0)
                    {
                        lineBuffer.Write(readBuffer.AsSpan(offset, segmentLength));
                    }

                    offset += segmentLength;
                    if (relativeNewLine < 0)
                    {
                        continue;
                    }

                    var jsonLine = lineBuffer.WrittenMemory.ToArray();
                    lineBuffer.Clear();
                    offset++;
                    if (jsonLine.Length > 0 && jsonLine[^1] == (byte)'\r')
                    {
                        Array.Resize(ref jsonLine, jsonLine.Length - 1);
                    }

                    if (jsonLine.Length == 0)
                    {
                        continue;
                    }

                    await HandleJsonLineAsync(jsonLine, generation, cancellationToken);
                }
            }

            if (!cancellationToken.IsCancellationRequested)
            {
                FaultTransport(generation, "The Codex app-server output stream closed.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected when the owned process is stopped.
        }
        catch (Exception ex)
        {
            LogSafeFailure("protocol output", ex);
            FaultTransport(generation, "The Codex app-server output stream failed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(readBuffer);
            ArrayPool<byte>.Shared.Return(readBuffer);
        }
    }

    private async Task PumpStandardErrorAsync(
        Process currentProcess,
        long generation,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        var totalBytes = 0;
        try
        {
            while (true)
            {
                var bytesRead = await currentProcess.StandardError.BaseStream.ReadAsync(
                    buffer.AsMemory(0, buffer.Length),
                    cancellationToken);
                if (bytesRead == 0)
                {
                    break;
                }

                totalBytes = checked(totalBytes + bytesRead);
                if (totalBytes > MaxStandardErrorBytes)
                {
                    FaultTransport(generation, "The Codex app-server diagnostic stream exceeded its safety limit.");
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected when the owned process is stopped.
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OverflowException)
        {
            LogSafeFailure("diagnostic stream", ex);
            FaultTransport(generation, "The Codex app-server diagnostic stream failed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task MonitorProcessAsync(
        Process currentProcess,
        long generation,
        CancellationToken cancellationToken)
    {
        try
        {
            await currentProcess.WaitForExitAsync(cancellationToken);
            if (!cancellationToken.IsCancellationRequested)
            {
                FaultTransport(generation, "The Codex app-server process exited.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected when the owned process is stopped.
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            LogSafeFailure("process monitor", ex);
            FaultTransport(generation, "The Codex app-server process monitor failed.");
        }
    }

    private async Task HandleJsonLineAsync(
        byte[] jsonLine,
        long generation,
        CancellationToken cancellationToken)
    {
        if (!IsCurrentGeneration(generation, requireReadyConnection: false))
        {
            return;
        }

        JsonDocument document;
        try
        {
            StrictUtf8.GetCharCount(jsonLine);
            document = JsonDocument.Parse(jsonLine, JsonDocumentOptions);
        }
        catch (Exception ex) when (ex is JsonException or DecoderFallbackException)
        {
            throw new CodexAppServerProtocolException("The Codex app-server emitted invalid JSON.", ex);
        }

        using (document)
        {
            if (!IsCurrentGeneration(generation, requireReadyConnection: false))
            {
                return;
            }

            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new CodexAppServerProtocolException("The Codex app-server emitted an invalid message.");
            }

            if (root.TryGetProperty("method", out var methodProperty)
                && methodProperty.ValueKind == JsonValueKind.String)
            {
                var method = methodProperty.GetString() ?? string.Empty;
                if (root.TryGetProperty("id", out var serverRequestId))
                {
                    await RejectServerRequestAsync(serverRequestId.Clone(), generation, cancellationToken);
                    return;
                }

                HandleNotification(method, root);
                return;
            }

            if (!root.TryGetProperty("id", out var responseId)
                || !TryReadRequestId(responseId, out var requestId))
            {
                throw new CodexAppServerProtocolException("The Codex app-server emitted an unrecognized message.");
            }

            if (!pendingRequests.TryGetValue(requestId, out var completion))
            {
                return;
            }

            if (root.TryGetProperty("error", out var error))
            {
                var errorCode = error.ValueKind == JsonValueKind.Object
                    && error.TryGetProperty("code", out var code)
                    && code.TryGetInt32(out var numericCode)
                        ? numericCode
                        : 0;
                completion.TrySetException(new CodexAppServerProtocolException(
                    $"The Codex app-server rejected a request (code {errorCode})."));
                return;
            }

            if (!root.TryGetProperty("result", out var result))
            {
                completion.TrySetException(new CodexAppServerProtocolException(
                    "The Codex app-server response did not contain a result."));
                return;
            }

            completion.TrySetResult(result.Clone());
        }
    }

    private void HandleNotification(string method, JsonElement root)
    {
        if (!root.TryGetProperty("params", out var parameters)
            || parameters.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (string.Equals(method, "account/login/completed", StringComparison.Ordinal))
        {
            HandleLoginCompletedNotification(parameters);
        }
        else if (string.Equals(method, "account/updated", StringComparison.Ordinal))
        {
            HandleAccountUpdatedNotification(parameters);
        }
    }

    private void HandleLoginCompletedNotification(JsonElement parameters)
    {
        if (!parameters.TryGetProperty("success", out var successProperty)
            || successProperty.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new CodexAppServerProtocolException("The Codex app-server emitted an invalid login notification.");
        }

        var success = successProperty.GetBoolean();
        var loginId = ReadRequiredString(parameters, "loginId", 256);

        var verifyCompletedLogin = false;
        lock (statusGate)
        {
            if (!loginAttemptReserved)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(activeLoginId))
            {
                earlyLoginCompletion = new LoginCompletionNotice(loginId, success);
                return;
            }

            if (!string.Equals(loginId, activeLoginId, StringComparison.Ordinal))
            {
                return;
            }

            verifyCompletedLogin = ApplyLoginCompletionLocked(success);
        }

        if (verifyCompletedLogin)
        {
            _ = VerifyCompletedLoginAsync();
        }
    }

    private void HandleAccountUpdatedNotification(JsonElement parameters)
    {
        if (!parameters.TryGetProperty("authMode", out var authMode))
        {
            return;
        }

        SocAgentCodexAccountStatus updated;
        if (authMode.ValueKind == JsonValueKind.String
            && string.Equals(authMode.GetString(), "chatgpt", StringComparison.Ordinal))
        {
            var planType = parameters.TryGetProperty("planType", out var plan)
                ? ReadSafePlanType(plan)
                : null;
            updated = new(
                true,
                true,
                "connected",
                planType,
                "The shared ChatGPT subscription is connected.");
        }
        else if (authMode.ValueKind == JsonValueKind.Null)
        {
            updated = new(
                true,
                false,
                "login_required",
                null,
                "ChatGPT login is required for soc-agent.");
        }
        else
        {
            updated = new(
                true,
                false,
                "unsupported_account",
                null,
                "The isolated Codex credential store is not using ChatGPT subscription login.");
        }

        PublishAccountStatus(updated);
    }

    private Task RejectServerRequestAsync(
        JsonElement requestId,
        long generation,
        CancellationToken cancellationToken)
    {
        var response = new Dictionary<string, object?>
        {
            ["id"] = requestId,
            ["error"] = new Dictionary<string, object?>
            {
                ["code"] = -32601,
                ["message"] = "This authentication-only client does not implement server requests."
            }
        };
        return WriteMessageAsync(
            response,
            cancellationToken,
            requireReadyConnection: false,
            expectedGeneration: generation);
    }

    private bool ApplyLoginCompletionLocked(bool success)
    {
        ClearLoginAttemptLocked();
        if (success)
        {
            loginStatus = new(
                true,
                false,
                "verifying",
                null,
                null,
                "ChatGPT login completed. Verifying the shared server account before enabling soc-agent.");
            return true;
        }

        loginStatus = new(
            true,
            false,
            "failed",
            null,
            null,
            "ChatGPT login did not complete. Start a new login and try again.");
        return false;
    }

    private async Task VerifyCompletedLoginAsync()
    {
        try
        {
            await ReadAccountStatusAsync(refreshToken: false, lifetimeCancellation.Token);
        }
        catch (OperationCanceledException) when (lifetimeCancellation.IsCancellationRequested)
        {
            // Expected during application shutdown.
        }
        catch (Exception ex)
        {
            SetUnavailableStatus("The completed ChatGPT login could not be verified safely.");
            LogSafeFailure("login verification", ex);
        }
    }

    private void PublishAccountStatus(SocAgentCodexAccountStatus status)
    {
        lock (statusGate)
        {
            accountStatus = status;
            if (loginAttemptReserved)
            {
                return;
            }

            loginStatus = status.IsConnected
                ? new(
                    true,
                    false,
                    "ready",
                    null,
                    null,
                    "The shared ChatGPT subscription is connected. An administrator can replace it with a new login.")
                : new(
                    status.IsAvailable,
                    false,
                    status.State,
                    null,
                    null,
                    status.OperatorMessage);
        }
    }

    private async Task WatchLoginTimeoutAsync(
        string loginId,
        CancellationTokenSource timeoutCancellation)
    {
        try
        {
            await Task.Delay(LoginTimeout, timeProvider, timeoutCancellation.Token);
        }
        catch (OperationCanceledException) when (timeoutCancellation.IsCancellationRequested)
        {
            timeoutCancellation.Dispose();
            return;
        }

        var shouldCancelServer = false;
        lock (statusGate)
        {
            if (loginAttemptReserved && string.Equals(activeLoginId, loginId, StringComparison.Ordinal))
            {
                loginTimeoutCancellation = null;
                loginAttemptReserved = false;
                activeLoginId = null;
                earlyLoginCompletion = null;
                loginStatus = new(
                    true,
                    false,
                    "timed_out",
                    null,
                    null,
                    "The ChatGPT login timed out. Start a new login to try again.");
                shouldCancelServer = true;
            }
        }

        if (shouldCancelServer)
        {
            using var boundedCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetimeCancellation.Token);
            boundedCancellation.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                await SendRequestAsync(
                    "account/login/cancel",
                    new Dictionary<string, object?>
                    {
                        ["loginId"] = loginId
                    },
                    TimeSpan.FromSeconds(5),
                    boundedCancellation.Token);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                LogSafeFailure("expired login cancellation", ex);
            }
        }

        timeoutCancellation.Dispose();
    }

    private async Task<SocAgentCodexCredential> ReadCredentialFileAsync(
        string currentCodexHome,
        CancellationToken cancellationToken)
    {
        var credentialPath = Path.GetFullPath(Path.Combine(currentCodexHome, "auth.json"));
        var expectedParent = Path.GetFullPath(currentCodexHome)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var actualParent = Path.GetDirectoryName(credentialPath)?
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!PathEquals(expectedParent, actualParent))
        {
            throw new CodexAppServerProtocolException("The Codex credential path was invalid.");
        }

        var fileInfo = new FileInfo(credentialPath);
        fileInfo.Refresh();
        if (!fileInfo.Exists
            || fileInfo.LinkTarget is not null
            || (fileInfo.Attributes & (FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) != 0
            || fileInfo.Length is <= 0 or > MaxCredentialFileBytes)
        {
            throw new CodexAppServerProtocolException("The Codex credential file was missing or unsafe.");
        }

        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(credentialPath);
            const UnixFileMode disallowed =
                UnixFileMode.GroupRead
                | UnixFileMode.GroupWrite
                | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead
                | UnixFileMode.OtherWrite
                | UnixFileMode.OtherExecute;
            if ((mode & disallowed) != 0)
            {
                throw new CodexAppServerProtocolException("The Codex credential file permissions were unsafe.");
            }
        }

        await using var stream = new FileStream(
            credentialPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            8192,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        fileInfo.Refresh();
        if (!fileInfo.Exists
            || fileInfo.LinkTarget is not null
            || (fileInfo.Attributes & (FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) != 0)
        {
            throw new CodexAppServerProtocolException("The Codex credential file changed to an unsafe file.");
        }

        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(credentialPath);
            const UnixFileMode disallowed =
                UnixFileMode.GroupRead
                | UnixFileMode.GroupWrite
                | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead
                | UnixFileMode.OtherWrite
                | UnixFileMode.OtherExecute;
            if ((mode & disallowed) != 0)
            {
                throw new CodexAppServerProtocolException("The Codex credential file permissions changed to an unsafe mode.");
            }
        }

        if (stream.Length is <= 0 or > MaxCredentialFileBytes)
        {
            throw new CodexAppServerProtocolException("The Codex credential file size was invalid.");
        }

        var buffer = ArrayPool<byte>.Shared.Rent(MaxCredentialFileBytes + 1);
        var bytesRead = 0;
        try
        {
            while (bytesRead <= MaxCredentialFileBytes)
            {
                var read = await stream.ReadAsync(
                    buffer.AsMemory(bytesRead, MaxCredentialFileBytes + 1 - bytesRead),
                    cancellationToken);
                if (read == 0)
                {
                    break;
                }

                bytesRead += read;
            }

            if (bytesRead == 0 || bytesRead > MaxCredentialFileBytes)
            {
                throw new CodexAppServerProtocolException("The Codex credential file exceeded its safety limit.");
            }

            using var document = JsonDocument.Parse(
                new ReadOnlyMemory<byte>(buffer, 0, bytesRead),
                JsonDocumentOptions);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("auth_mode", out var authMode)
                || authMode.ValueKind != JsonValueKind.String
                || !string.Equals(authMode.GetString(), "chatgpt", StringComparison.Ordinal)
                || !root.TryGetProperty("tokens", out var tokens)
                || tokens.ValueKind != JsonValueKind.Object)
            {
                throw new CodexAppServerProtocolException("The Codex credential file schema was invalid.");
            }

            var accessToken = ReadRequiredString(tokens, "access_token", 512 * 1024);
            var accountId = ReadRequiredString(tokens, "account_id", 512);
            ValidateCredentialValue(accessToken, minimumLength: 20);
            ValidateCredentialValue(accountId, minimumLength: 1);
            return new SocAgentCodexCredential(accessToken, accountId);
        }
        catch (JsonException ex)
        {
            throw new CodexAppServerProtocolException("The Codex credential file could not be parsed safely.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, Math.Min(bytesRead, buffer.Length)));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private ProcessStartInfo CreateStartInfo(
        string executable,
        string stateDirectory,
        string syntheticHome,
        string temporaryDirectory,
        string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("app-server");
        startInfo.ArgumentList.Add("--listen");
        startInfo.ArgumentList.Add("stdio://");
        startInfo.ArgumentList.Add("--strict-config");
        AddConfigOverride(startInfo, "cli_auth_credentials_store=\"file\"");
        AddConfigOverride(startInfo, "check_for_update_on_startup=false");
        AddConfigOverride(startInfo, "web_search=\"disabled\"");
        foreach (var feature in new[]
        {
            "apps",
            "goals",
            "hooks",
            "multi_agent",
            "plugins",
            "remote_plugin",
            "shell_tool",
            "unified_exec"
        })
        {
            startInfo.ArgumentList.Add("--disable");
            startInfo.ArgumentList.Add(feature);
        }

        startInfo.Environment.Clear();
        startInfo.Environment["CODEX_HOME"] = stateDirectory;
        startInfo.Environment["HOME"] = syntheticHome;
        startInfo.Environment["TMPDIR"] = temporaryDirectory;
        startInfo.Environment["RUST_LOG"] = "error";
        startInfo.Environment["LANG"] = "C.UTF-8";
        startInfo.Environment["PATH"] = BuildRestrictedPath(executable);
        CopyAllowedEnvironmentVariables(startInfo.Environment);
        return startInfo;
    }

    private static void AddConfigOverride(ProcessStartInfo startInfo, string value)
    {
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add(value);
    }

    private static void CopyAllowedEnvironmentVariables(IDictionary<string, string?> target)
    {
        foreach (var name in new[]
        {
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "https_proxy",
            "http_proxy",
            "all_proxy",
            "no_proxy",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "CODEX_CA_CERTIFICATE"
        })
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(value))
            {
                target[name] = value;
            }
        }
    }

    private string ResolveCodexExecutable()
    {
        var configured = options.ExecutablePath?.Trim();
        if (!string.IsNullOrWhiteSpace(configured))
        {
            if (configured.StartsWith('~'))
            {
                configured = ExpandHomeDirectory(configured);
            }

            if (Path.IsPathRooted(configured))
            {
                return ValidateExecutable(configured);
            }

            if (configured.Contains(Path.DirectorySeparatorChar)
                || configured.Contains(Path.AltDirectorySeparatorChar))
            {
                throw new CodexAppServerProtocolException("The configured Codex executable path must be absolute.");
            }

            return FindExecutableOnPath(configured)
                ?? throw new CodexAppServerProtocolException("The configured Codex executable was not found.");
        }

        var fromPath = FindExecutableOnPath(OperatingSystem.IsWindows() ? "codex.exe" : "codex");
        if (fromPath is not null)
        {
            return fromPath;
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(home))
        {
            var fallback = Path.Combine(home, ".local", "bin", OperatingSystem.IsWindows() ? "codex.exe" : "codex");
            if (File.Exists(fallback))
            {
                return ValidateExecutable(fallback);
            }
        }

        throw new CodexAppServerProtocolException("The official Codex executable was not found.");
    }

    private static string? FindExecutableOnPath(string fileName)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        foreach (var entry in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!Path.IsPathRooted(entry))
            {
                continue;
            }

            var candidate = Path.Combine(entry, fileName);
            if (File.Exists(candidate))
            {
                return ValidateExecutable(candidate);
            }
        }

        return null;
    }

    private static string ValidateExecutable(string candidate)
    {
        var fullPath = Path.GetFullPath(candidate);
        var info = new FileInfo(fullPath);
        info.Refresh();
        if (!info.Exists || (info.Attributes & (FileAttributes.Directory | FileAttributes.Device)) != 0)
        {
            throw new CodexAppServerProtocolException("The Codex executable path was invalid.");
        }

        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(fullPath);
            const UnixFileMode executableBits =
                UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
            if ((mode & executableBits) == 0)
            {
                throw new CodexAppServerProtocolException("The Codex executable was not executable.");
            }
        }

        return fullPath;
    }

    private string ResolveConfiguredDirectory(string configured, string defaultValue)
    {
        var value = string.IsNullOrWhiteSpace(configured) ? defaultValue : configured.Trim();
        if (value.StartsWith('~'))
        {
            return Path.GetFullPath(ExpandHomeDirectory(value));
        }

        if (Path.IsPathRooted(value))
        {
            return Path.GetFullPath(value);
        }

        var repositoryRoot = FindRepositoryRoot();
        var localRoot = Path.GetFullPath(Path.Combine(repositoryRoot, ".local"));
        var resolved = Path.GetFullPath(Path.Combine(repositoryRoot, value));
        if (PathEquals(resolved, localRoot) || !IsSameOrDescendant(resolved, localRoot))
        {
            throw new CodexAppServerProtocolException(
                "Relative Codex state paths must stay under the project-local .local directory.");
        }

        return resolved;
    }

    private string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(Path.GetFullPath(hostEnvironment.ContentRootPath));
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "VERSION"))
                && File.Exists(Path.Combine(current.FullName, ".gitignore")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        return Path.GetFullPath(hostEnvironment.ContentRootPath);
    }

    private static string ExpandHomeDirectory(string value)
    {
        if (value.Length == 1 || (value[1] != Path.DirectorySeparatorChar && value[1] != Path.AltDirectorySeparatorChar))
        {
            throw new CodexAppServerProtocolException("The configured home-relative path was invalid.");
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home))
        {
            throw new CodexAppServerProtocolException("The user profile directory could not be resolved.");
        }

        return Path.Combine(home, value[2..]);
    }

    private void ValidateSafeDirectoryTarget(string path)
    {
        var fullPath = Path.GetFullPath(path)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = Path.GetPathRoot(fullPath)?
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var repositoryRoot = FindRepositoryRoot()
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var contentRoot = Path.GetFullPath(hostEnvironment.ContentRootPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var globalCodexHome = string.IsNullOrWhiteSpace(userHome)
            ? null
            : Path.Combine(userHome, ".codex");
        var legacyPiHome = string.IsNullOrWhiteSpace(userHome)
            ? null
            : Path.Combine(userHome, ".pi");

        if (string.IsNullOrWhiteSpace(fullPath)
            || PathEquals(fullPath, root)
            || PathEquals(fullPath, repositoryRoot)
            || PathEquals(fullPath, contentRoot)
            || (!string.IsNullOrWhiteSpace(userHome) && PathEquals(fullPath, userHome))
            || IsSameOrDescendant(fullPath, globalCodexHome)
            || IsSameOrDescendant(fullPath, legacyPiHome))
        {
            throw new CodexAppServerProtocolException("The configured Codex state path was too broad.");
        }
    }

    private static void EnsurePrivateDirectory(string path)
    {
        ValidateNoLinkedDirectoryComponents(path);
        Directory.CreateDirectory(path);
        ValidateNoLinkedDirectoryComponents(path);
        var info = new DirectoryInfo(path);
        info.Refresh();
        if (!info.Exists
            || info.LinkTarget is not null
            || (info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new CodexAppServerProtocolException("A Codex state directory was missing or unsafe.");
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void ValidateNoLinkedDirectoryComponents(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath)
            ?? throw new CodexAppServerProtocolException("A Codex state directory root could not be resolved.");
        var relative = fullPath[root.Length..];
        var current = root;
        foreach (var segment in relative.Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            var info = new DirectoryInfo(current);
            info.Refresh();
            if (!info.Exists)
            {
                continue;
            }

            if (info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new CodexAppServerProtocolException("A Codex state directory ancestor was linked or unsafe.");
            }
        }
    }

    private static string BuildRestrictedPath(string executable)
    {
        var entries = new List<string>();
        var executableDirectory = Path.GetDirectoryName(executable);
        if (!string.IsNullOrWhiteSpace(executableDirectory))
        {
            entries.Add(executableDirectory);
        }

        if (!OperatingSystem.IsWindows())
        {
            entries.Add("/usr/local/bin");
            entries.Add("/usr/bin");
            entries.Add("/bin");
        }

        return string.Join(Path.PathSeparator, entries.Distinct(PathComparer));
    }

    private static void ValidateInitializedCodexHome(JsonElement result, string expectedCodexHome)
    {
        var returnedCodexHome = ReadRequiredString(result, "codexHome", 4096);
        if (!Path.IsPathRooted(returnedCodexHome)
            || !PathEquals(Path.GetFullPath(returnedCodexHome), Path.GetFullPath(expectedCodexHome)))
        {
            throw new CodexAppServerProtocolException("The Codex app-server did not use the isolated credential store.");
        }
    }

    private static string ReadRequiredString(JsonElement element, string propertyName, int maximumLength)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String)
        {
            throw new CodexAppServerProtocolException("The Codex app-server response was missing a required value.");
        }

        var value = property.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
        {
            throw new CodexAppServerProtocolException("The Codex app-server response contained an invalid value.");
        }

        return value;
    }

    private static string? ReadSafePlanType(JsonElement accountOrPlan)
    {
        JsonElement plan;
        if (accountOrPlan.ValueKind == JsonValueKind.Object)
        {
            if (!accountOrPlan.TryGetProperty("planType", out plan))
            {
                return null;
            }
        }
        else
        {
            plan = accountOrPlan;
        }

        if (plan.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (plan.ValueKind != JsonValueKind.String)
        {
            return "unknown";
        }

        var value = plan.GetString();
        return value is not null && KnownPlanTypes.Contains(value) ? value : "unknown";
    }

    private static void ValidateDeviceLoginValues(string verificationUrl, string userCode)
    {
        var uri = new Uri(verificationUrl, UriKind.Absolute);
        if (!string.Equals(uri.AbsoluteUri, DeviceVerificationUrl, StringComparison.Ordinal)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || !string.Equals(uri.Host, "auth.openai.com", StringComparison.OrdinalIgnoreCase)
            || !uri.IsDefaultPort
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !DeviceCodePattern.IsMatch(userCode))
        {
            throw new CodexAppServerProtocolException("The Codex app-server returned an unsafe device login response.");
        }
    }

    private static void ValidateCredentialValue(string value, int minimumLength)
    {
        if (value.Length < minimumLength || value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new CodexAppServerProtocolException("The Codex credential file contained an invalid credential value.");
        }
    }

    private static bool TryReadRequestId(JsonElement value, out long requestId)
    {
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out requestId))
        {
            return true;
        }

        if (value.ValueKind == JsonValueKind.String
            && long.TryParse(value.GetString(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out requestId))
        {
            return true;
        }

        requestId = 0;
        return false;
    }

    private bool IsConnectionReady()
    {
        lock (processGate)
        {
            return connectionReady && process is not null && !process.HasExited;
        }
    }

    private long CaptureTransportGeneration(bool requireReadyConnection)
    {
        lock (processGate)
        {
            if (process is null || process.HasExited || (requireReadyConnection && !connectionReady))
            {
                throw new CodexAppServerProtocolException("The Codex app-server transport is unavailable.");
            }

            return processGeneration;
        }
    }

    private bool IsCurrentGeneration(long generation, bool requireReadyConnection)
    {
        lock (processGate)
        {
            return generation == processGeneration
                && process is not null
                && !process.HasExited
                && (!requireReadyConnection || connectionReady);
        }
    }

    private void FaultTransport(long generation, string operatorSafeMessage)
    {
        Process? failedProcess;
        CancellationTokenSource? failedCancellation;
        lock (processGate)
        {
            if (generation != processGeneration)
            {
                return;
            }

            connectionReady = false;
            Interlocked.Increment(ref processGeneration);
            failedProcess = process;
            failedCancellation = processCancellation;
            FailAllPendingRequests(new CodexAppServerProtocolException(operatorSafeMessage));
            if (!stopping)
            {
                SetTransportFaultStatus();
            }
        }

        failedCancellation?.Cancel();
        TryKill(failedProcess);
    }

    private void ResetFailedProcess()
    {
        Process? previousProcess;
        CancellationTokenSource? previousCancellation;
        string? previousSessionWorkingDirectory;
        lock (processGate)
        {
            previousProcess = process;
            previousCancellation = processCancellation;
            previousSessionWorkingDirectory = sessionWorkingDirectory;
            connectionReady = false;
            process = null;
            processCancellation = null;
            stdoutPump = null;
            stderrPump = null;
            processMonitor = null;
            codexHome = null;
            sessionWorkingDirectory = null;
        }

        previousCancellation?.Cancel();
        TryKill(previousProcess);
        previousCancellation?.Dispose();
        previousProcess?.Dispose();
        CleanupEmptySessionWorkingDirectory(previousSessionWorkingDirectory);
        FailAllPendingRequests(new CodexAppServerProtocolException("The Codex app-server connection was reset."));
    }

    private void FailAllPendingRequests(Exception exception)
    {
        foreach (var entry in pendingRequests)
        {
            if (pendingRequests.TryRemove(entry.Key, out var completion))
            {
                completion.TrySetException(exception);
            }
        }
    }

    private static void TryKill(Process? target)
    {
        if (target is null)
        {
            return;
        }

        try
        {
            if (!target.HasExited)
            {
                target.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            // The child has already exited or cannot be killed on this platform.
        }
    }

    private static void CleanupEmptySessionWorkingDirectory(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return;
        }

        try
        {
            Directory.Delete(directory, recursive: false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            // Never recursively remove an app-server working directory.
        }
    }

    private void SetStartingStatus()
    {
        lock (statusGate)
        {
            accountStatus = new(
                false,
                false,
                "starting",
                null,
                "Starting the SIEM-managed ChatGPT login service.");
            if (!loginAttemptReserved)
            {
                loginStatus = new(
                    false,
                    false,
                    "starting",
                    null,
                    null,
                    "Starting the SIEM-managed ChatGPT login service.");
            }
        }
    }

    private void SetAvailableStatus()
    {
        lock (statusGate)
        {
            if (!accountStatus.IsConnected)
            {
                accountStatus = new(
                    true,
                    false,
                    "login_required",
                    null,
                    "ChatGPT login is required for soc-agent.");
            }

            if (!loginAttemptReserved)
            {
                loginStatus = new(
                    true,
                    false,
                    accountStatus.IsConnected ? "ready" : "login_required",
                    null,
                    null,
                    accountStatus.IsConnected
                        ? "The shared ChatGPT subscription is connected. An administrator can replace it with a new login."
                        : "An administrator can start the ChatGPT device login.");
            }
        }
    }

    private void SetUnavailableStatus(string message)
    {
        lock (statusGate)
        {
            if (loginAttemptReserved)
            {
                ClearLoginAttemptLocked();
            }

            accountStatus = new(false, false, "unavailable", null, message);
            loginStatus = new(false, false, "unavailable", null, null, message);
        }
    }

    private void SetTransportFaultStatus()
    {
        lock (statusGate)
        {
            if (loginAttemptReserved)
            {
                ClearLoginAttemptLocked();
            }

            accountStatus = new(
                false,
                false,
                "unavailable",
                null,
                "The SIEM-managed ChatGPT login service stopped unexpectedly.");
            loginStatus = new(
                true,
                false,
                "failed",
                null,
                null,
                "The ChatGPT login service stopped unexpectedly. Start a new login to retry.");
        }
    }

    private void SetDisabledStatus()
    {
        lock (statusGate)
        {
            accountStatus = new(
                false,
                false,
                "disabled",
                null,
                "The SIEM-managed ChatGPT login service is disabled by server configuration.");
            loginStatus = new(
                false,
                false,
                "disabled",
                null,
                null,
                "The SIEM-managed ChatGPT login service is disabled by server configuration.");
        }
    }

    private void SetUnsupportedPlatformStatus()
    {
        lock (statusGate)
        {
            accountStatus = new(
                false,
                false,
                "unsupported_platform",
                null,
                "SIEM-managed ChatGPT login is not supported on a Windows SIEM server in this build because an owner-only credential ACL cannot yet be enforced.");
            loginStatus = new(
                false,
                false,
                "unsupported_platform",
                null,
                null,
                accountStatus.OperatorMessage);
        }
    }

    private void ClearLoginAttemptLocked()
    {
        loginAttemptReserved = false;
        activeLoginId = null;
        earlyLoginCompletion = null;
        var cancellation = loginTimeoutCancellation;
        loginTimeoutCancellation = null;
        cancellation?.Cancel();
        cancellation?.Dispose();
    }

    private void RestoreWaitingLoginStatus()
    {
        lock (statusGate)
        {
            if (!loginAttemptReserved)
            {
                return;
            }

            loginStatus = loginStatus with
            {
                State = "waiting_for_user",
                OperatorMessage = "The ChatGPT login is still active. Try cancelling again if needed."
            };
        }
    }

    private void CancelLoginTimeout()
    {
        lock (statusGate)
        {
            var cancellation = loginTimeoutCancellation;
            loginTimeoutCancellation = null;
            cancellation?.Cancel();
            cancellation?.Dispose();
        }
    }

    private void LogSafeFailure(string operation, Exception exception)
    {
        logger.LogWarning(
            "The soc-agent Codex app-server {Operation} failed ({FailureType}). No credential or provider response content was logged.",
            operation,
            exception.GetType().Name);
    }

    private static bool PathEquals(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return false;
        }

        return string.Equals(left, right, PathComparison);
    }

    private static bool IsSameOrDescendant(string path, string? protectedRoot)
    {
        if (string.IsNullOrWhiteSpace(protectedRoot))
        {
            return false;
        }

        var normalizedPath = Path.GetFullPath(path)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedRoot = Path.GetFullPath(protectedRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return PathEquals(normalizedPath, normalizedRoot)
            || normalizedPath.StartsWith(
                normalizedRoot + Path.DirectorySeparatorChar,
                PathComparison);
    }

    private static StringComparer PathComparer =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private sealed record LoginCompletionNotice(string? LoginId, bool Success);

    private sealed class CodexAppServerProtocolException : Exception
    {
        public CodexAppServerProtocolException(string message)
            : base(message)
        {
        }

        public CodexAppServerProtocolException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
