using System.Text.Json;
using System.Text.Json.Serialization;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Api.Platform;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Api.SocAgent;
using Challenger.Siem.Api.Storage;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 2 * 1024 * 1024;
});

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
    options.SerializerOptions.DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

builder.Services.AddDataProtection();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton<OperatorPasswordHasher>();
builder.Services.AddSingleton(sp =>
{
    var configuration = sp.GetRequiredService<IConfiguration>();
    var connectionString = configuration.GetConnectionString("SiemDatabase");
    if (string.IsNullOrWhiteSpace(connectionString))
    {
        throw new InvalidOperationException("ConnectionStrings:SiemDatabase is required.");
    }

    return NpgsqlDataSource.Create(connectionString);
});
builder.Services.AddScoped<AgentRepository>();
builder.Services.AddScoped<OperatorRepository>();
builder.Services.AddScoped<SecurityAuditRepository>();
builder.Services.AddScoped<OperatorCookieEvents>();
builder.Services.AddScoped<AgentAuthenticator>();
builder.Services.AddScoped<EventRepository>();
builder.Services.AddScoped<RetentionRepository>();
builder.Services.AddScoped<HeartbeatRepository>();
builder.Services.AddScoped<SourceHealthRepository>();
builder.Services.AddScoped<TelemetryCoverageRepository>();
builder.Services.AddScoped<AssetInventoryRepository>();
builder.Services.AddScoped<AlertRepository>();
builder.Services.AddScoped<SocAgentRepository>();
builder.Services.AddScoped<SocAgentProviderStatusService>();
builder.Services.AddHttpClient<ISocAgentModelProvider, OpenAiSocAgentModelProvider>((serviceProvider, client) =>
{
    var configured = serviceProvider.GetRequiredService<IOptions<SocAgentOptions>>().Value;
    client.Timeout = TimeSpan.FromSeconds(Math.Clamp(configured.RequestTimeoutSeconds, 5, 120));
});
builder.Services.AddHttpClient<SocAgentSubscriptionOAuthConnectService>((serviceProvider, client) =>
{
    var configured = serviceProvider.GetRequiredService<IOptions<SocAgentOptions>>().Value;
    client.Timeout = TimeSpan.FromSeconds(Math.Clamp(configured.RequestTimeoutSeconds, 5, 120));
});
builder.Services.AddScoped<SocAgentService>();
builder.Services.AddSingleton<SocAgentLiveRunRegistry>();
builder.Services.AddScoped<SocAgentLiveRunCoordinator>();
builder.Services.AddSingleton<DetectionEngine>();
builder.Services.AddScoped<IngestionErrorRepository>();
builder.Services.AddScoped<InvestigationGraphRepository>();
builder.Services.AddScoped<ReviewRepository>();
builder.Services.Configure<ReviewOptions>(builder.Configuration.GetSection(ReviewOptions.SectionName));
builder.Services.Configure<SocAgentOptions>(builder.Configuration.GetSection(SocAgentOptions.SectionName));
builder.Services.AddOptions<ManagedRetentionOptions>()
    .Bind(builder.Configuration.GetSection(ManagedRetentionOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<ManagedRetentionOptions>, ManagedRetentionOptionsValidator>();
builder.Services.AddHostedService<ManagedRetentionHostedService>();
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/");
    options.Conventions.AllowAnonymousToPage("/Login");
});
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = OperatorAuthentication.SmartScheme;
        options.DefaultChallengeScheme = OperatorAuthentication.SmartScheme;
    })
    .AddPolicyScheme(OperatorAuthentication.SmartScheme, null, options => options.ForwardDefaultSelector = context =>
    {
        var pathValue = context.Request.Path.Value ?? string.Empty;
        var isAgentTransport = pathValue.StartsWith("/api/v1/agents/", StringComparison.OrdinalIgnoreCase)
            || pathValue.StartsWith("/api/v1/ingest/", StringComparison.OrdinalIgnoreCase);
        // Agent transport uses AgentAuthenticator only; never invoke operator bearer handling on those routes.
        if (isAgentTransport)
        {
            return CookieAuthenticationDefaults.AuthenticationScheme;
        }

        return context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? OperatorAuthentication.BearerScheme
            : CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddScheme<AuthenticationSchemeOptions, OperatorBearerHandler>(OperatorAuthentication.BearerScheme, null)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.AccessDeniedPath = "/forbidden";
        options.Cookie.Name = ".ChallengerSiem.Operator";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
        options.Cookie.MaxAge = OperatorRepository.SessionLifetime;
        options.ExpireTimeSpan = OperatorRepository.SessionLifetime;
        options.SlidingExpiration = false;
        options.EventsType = typeof(OperatorCookieEvents);
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("analyst", policy => policy.RequireAssertion(c => OperatorAuthorization.HasPermission(OperatorAuthorization.Role(c.User), OperatorPermission.ReviewSensitive)));
    options.AddPolicy("investigations", policy => policy.RequireAssertion(c => OperatorAuthorization.HasPermission(OperatorAuthorization.Role(c.User), OperatorPermission.ManageInvestigations)));
    options.AddPolicy("detections", policy => policy.RequireAssertion(c => OperatorAuthorization.HasPermission(OperatorAuthorization.Role(c.User), OperatorPermission.ManageDetections)));
    options.AddPolicy("admin", policy => policy.RequireRole(OperatorRoles.Admin));
});

var app = builder.Build();

// Local operator bootstrap/recovery/token rotation only needs the database connection string.
// Keep enrollment-token validation for normal web/API server startup.
if (args.Length >= 2 && string.Equals(args[0], "operator", StringComparison.Ordinal))
{
    if (string.IsNullOrWhiteSpace(app.Configuration.GetConnectionString("SiemDatabase")))
    {
        throw new InvalidOperationException(
            "Missing required Challenger SIEM configuration: ConnectionStrings:SiemDatabase. Set this value with an environment variable or ignored local settings file. Secret values are intentionally not shown.");
    }

    var commandExit = await OperatorAccountCommand.TryRunAsync(args, app.Services, CancellationToken.None);
    if (commandExit.HasValue)
    {
        Environment.ExitCode = commandExit.Value;
        return;
    }
}

StartupConfigurationValidator.ValidateRequiredConfiguration(app.Configuration);

app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers.TryAdd("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; connect-src 'self'");
    context.Response.Headers.TryAdd("X-Content-Type-Options", "nosniff");
    context.Response.Headers.TryAdd("Referrer-Policy", "same-origin");
    if (!app.Environment.IsDevelopment() && !context.Request.IsHttps)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { error = "https_required" });
        return;
    }

    await next();
});
app.UseStaticFiles();
app.UseAuthentication();
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api")
        && context.Request.Method is not ("GET" or "HEAD" or "OPTIONS")
        && context.User.Identity?.IsAuthenticated == true
        && !context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { error = "csrf_safe_bearer_required" });
        return;
    }
    await next();
});
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? string.Empty;
    var isOperatorApi = path.StartsWith("/api/v1/", StringComparison.Ordinal)
        && !path.StartsWith("/api/v1/agents/", StringComparison.Ordinal)
        && !path.StartsWith("/api/v1/ingest/", StringComparison.Ordinal);
    if (isOperatorApi)
    {
        var audit = context.RequestServices.GetRequiredService<SecurityAuditRepository>();
        var authenticated = context.User.Identity?.IsAuthenticated == true;
        var allowed = authenticated && context.RequestServices.GetRequiredService<TokenService>().HasOperatorAccess(context);
        await audit.RecordAsync(OperatorAuthentication.OperatorId(context.User), context.User.Identity?.Name,
            "operator.api_access", allowed ? "success" : "denied", "route", path, context,
            new Dictionary<string,object?> { ["method"] = context.Request.Method }, context.RequestAborted);
    }
    await next();
});
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/api/v1/operators", async Task<IResult> (OperatorCreateRequest request, HttpContext context, OperatorRepository operators, SecurityAuditRepository audit, CancellationToken cancellationToken) =>
{
    if (!OperatorAuthorization.HasPermission(OperatorAuthorization.Role(context.User), OperatorPermission.ManageOperators)) return Results.Forbid();
    try
    {
        var created = await operators.CreateAsync(request.Username, request.DisplayName, request.Role, request.Password, false, cancellationToken);
        await audit.RecordAsync(OperatorAuthentication.OperatorId(context.User), context.User.Identity?.Name, "operator.create", "success", "operator", created.OperatorId.ToString(), context, new Dictionary<string,object?> { ["role"] = created.Role }, cancellationToken);
        return Results.Ok(new { created.OperatorId, created.Username, created.DisplayName, created.Role, created.Enabled });
    }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string,string[]> { ["operator"] = new[] { ex.Message } }); }
}).RequireAuthorization("admin");

app.MapPost("/api/v1/operators/me/password", async Task<IResult> (OperatorPasswordChangeRequest request, HttpContext context, OperatorRepository operators, SecurityAuditRepository audit, CancellationToken cancellationToken) =>
{
    var id = OperatorAuthentication.OperatorId(context.User); if (!id.HasValue) return Results.Unauthorized();
    if (!await operators.VerifyPasswordAsync(id.Value, request.CurrentPassword, cancellationToken))
    {
        await audit.RecordAsync(id, context.User.Identity?.Name, "operator.password.change", "failure", "operator", id.ToString(), context, null, cancellationToken);
        return Results.Unauthorized();
    }
    try { await operators.ChangePasswordAsync(id.Value, request.NewPassword, false, cancellationToken); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string,string[]> { ["new_password"] = new[] { ex.Message } }); }
    await audit.RecordAsync(id, context.User.Identity?.Name, "operator.password.change", "success", "operator", id.ToString(), context, null, cancellationToken);
    return Results.Ok(new { status = "changed", sessions_revoked = true });
}).RequireAuthorization();

app.MapPost("/api/v1/operators/me/api-token/rotate", async Task<IResult> (HttpContext context, OperatorRepository operators, SecurityAuditRepository audit, CancellationToken cancellationToken) =>
{
    var id=OperatorAuthentication.OperatorId(context.User); if(!id.HasValue)return Results.Unauthorized(); var token=await operators.RotateApiTokenAsync(id.Value,cancellationToken);
    await audit.RecordAsync(id,context.User.Identity?.Name,"operator.api_token.rotate","success","operator",id.ToString(),context,null,cancellationToken);
    return Results.Ok(new { api_token=token, shown_once=true, sessions_revoked=true });
}).RequireAuthorization();

app.MapPost("/api/v1/agents/register", async Task<IResult> (
    HttpContext context,
    AgentRegistrationRequest request,
    AgentRepository agents,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    var enrollmentToken = configuration["Auth:EnrollmentToken"];
    if (string.IsNullOrWhiteSpace(enrollmentToken))
    {
        return Results.Problem("Enrollment token is not configured.", statusCode: StatusCodes.Status500InternalServerError);
    }

    var providedToken = context.Request.Headers["X-Enrollment-Token"].FirstOrDefault();
    if (!tokens.FixedTimeEquals(enrollmentToken, providedToken))
    {
        return Results.Unauthorized();
    }

    var validationErrors = RequestValidation.ValidateRegistration(request);
    if (validationErrors.Count > 0)
    {
        return Results.ValidationProblem(validationErrors);
    }


    var apiToken = tokens.GenerateAgentToken();
    var apiTokenHash = tokens.HashToken(apiToken);
    await agents.UpsertAgentAsync(request, apiTokenHash, cancellationToken);

    return Results.Ok(new AgentRegistrationResponse
    {
        AgentId = request.AgentId,
        ApiToken = apiToken,
        RegisteredAt = DateTimeOffset.UtcNow
    });
});

app.MapPost("/api/v1/agents/heartbeat", async Task<IResult> (
    HttpContext context,
    HeartbeatRequest request,
    AgentAuthenticator authenticator,
    HeartbeatRepository heartbeats,
    CancellationToken cancellationToken) =>
{
    if (!await authenticator.AuthenticateAsync(context, request.AgentId, cancellationToken))
    {
        return Results.Unauthorized();
    }

    var validationErrors = RequestValidation.ValidateHeartbeat(request);
    if (validationErrors.Count > 0)
    {
        return Results.ValidationProblem(validationErrors);
    }


    await heartbeats.InsertHeartbeatAsync(request, cancellationToken);
    return Results.Ok(new { status = "accepted" });
});

app.MapPost("/api/v1/agents/inventory", async Task<IResult> (
    HttpContext context,
    AssetInventoryBatchRequest request,
    AgentAuthenticator authenticator,
    AssetInventoryRepository inventory,
    CancellationToken cancellationToken) =>
{
    if (!await authenticator.AuthenticateAsync(context, request.AgentId, cancellationToken))
    {
        return Results.Unauthorized();
    }

    var validationErrors = RequestValidation.ValidateInventoryBatch(request);
    if (validationErrors.Count > 0)
    {
        return Results.ValidationProblem(validationErrors);
    }

    foreach (var snapshot in request.Snapshots)
    {
        await inventory.StoreAsync(snapshot, cancellationToken);
    }

    return Results.Ok(new { status = "accepted", snapshots = request.Snapshots.Count });
});

app.MapPost("/api/v1/ingest/events", async Task<IResult> (
    HttpContext context,
    IngestBatchRequest request,
    AgentAuthenticator authenticator,
    EventRepository events,
    AlertRepository alerts,
    DetectionEngine detectionEngine,
    IngestionErrorRepository ingestionErrors,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!await authenticator.AuthenticateAsync(context, request.AgentId, cancellationToken))
    {
        return Results.Unauthorized();
    }

    var maxEventsPerBatch = ParseIntOrDefault(configuration["Ingestion:MaxEventsPerBatch"], 500);
    var validationErrors = RequestValidation.ValidateBatch(request, maxEventsPerBatch);
    if (validationErrors.Count > 0)
    {
        await ingestionErrors.RecordValidationErrorsAsync(request, validationErrors, cancellationToken);
        return Results.ValidationProblem(validationErrors);
    }

    var result = await events.StoreEventsAsync(request, cancellationToken);
    await alerts.RunLinuxDetectionsAsync(request, result.AcceptedEventIds, detectionEngine, cancellationToken);
    return Results.Ok(new IngestBatchResponse
    {
        BatchId = request.BatchId,
        Accepted = result.Accepted,
        Rejected = 0,
        Duplicates = result.Duplicates,
        AcceptedEventIds = result.AcceptedEventIds,
        DuplicateEventIds = result.DuplicateEventIds,
        RejectedEventIds = Array.Empty<Guid>()
    });
});

app.MapGet("/api/v1/events", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var query = EventSearchQuery.FromQuery(context.Request.Query);
    if (query.ValidationErrors.Count > 0)
    {
        return Results.ValidationProblem(query.ValidationErrors.GroupBy(item => item.Field).ToDictionary(item => item.Key, item => item.Select(error => error.Message).ToArray()));
    }

    var page = await events.SearchEventsPageForOperatorAsync(query, OperatorAuthorization.Role(context.User)!, cancellationToken);
    return Results.Ok(new EventSearchResponse
    {
        Events = page.Events,
        Page = page.Page,
        ActiveFilters = page.ActiveFilters,
        ResultScope = page.ResultScope,
        Redaction = page.RedactionNotice
    });
});

app.MapGet("/api/v1/events/timeline", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var query = EventSearchQuery.FromQuery(context.Request.Query);
    if (query.ValidationErrors.Count > 0)
    {
        return Results.ValidationProblem(query.ValidationErrors.GroupBy(item => item.Field).ToDictionary(item => item.Key, item => item.Select(error => error.Message).ToArray()));
    }

    var timeline = await events.GetTimelineAsync(query, OperatorAuthorization.Role(context.User)!, cancellationToken);
    return Results.Ok(new EventTimelineResponse
    {
        Buckets = timeline.Buckets,
        BucketSeconds = timeline.BucketSeconds
    });
});

app.MapGet("/api/v1/events/saved-searches", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var operatorId = OperatorAuthentication.OperatorId(context.User);
    return operatorId.HasValue ? Results.Ok(new { saved_searches = await events.ListSavedSearchesAsync(operatorId.Value, cancellationToken) }) : Results.Unauthorized();
});

app.MapPost("/api/v1/events/saved-searches", async Task<IResult> (
    SavedEventSearchRequest request,
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var operatorId = OperatorAuthentication.OperatorId(context.User);
    if (!operatorId.HasValue) return Results.Unauthorized();
    try
    {
        var canShare = OperatorAuthorization.HasPermission(OperatorAuthorization.Role(context.User), OperatorPermission.ReviewSensitive);
        var saved = await events.SaveSearchAsync(request, operatorId.Value, context.User.Identity?.Name ?? "operator", canShare, cancellationToken);
        await audit.RecordAsync(operatorId, context.User.Identity?.Name, "event_search.saved.create", "success", "saved_event_search", saved.SavedSearchId.ToString(), context, new Dictionary<string, object?> { ["visibility"] = saved.Visibility, ["version"] = saved.Version }, cancellationToken);
        return Results.Ok(saved);
    }
    catch (UnauthorizedAccessException)
    {
        await audit.RecordAsync(operatorId, context.User.Identity?.Name, "event_search.saved.create", "denied", "saved_event_search", null, context, null, cancellationToken);
        return Results.Forbid();
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["saved_search"] = new[] { ex.Message } });
    }
});

app.MapPut("/api/v1/events/saved-searches/{savedSearchId:guid}", async Task<IResult> (
    Guid savedSearchId,
    SavedEventSearchRequest request,
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var operatorId = OperatorAuthentication.OperatorId(context.User);
    if (!operatorId.HasValue) return Results.Unauthorized();
    try
    {
        var canShare = OperatorAuthorization.HasPermission(OperatorAuthorization.Role(context.User), OperatorPermission.ReviewSensitive);
        var saved = await events.SaveSearchAsync(request, operatorId.Value, context.User.Identity?.Name ?? "operator", canShare, cancellationToken, savedSearchId);
        await audit.RecordAsync(operatorId, context.User.Identity?.Name, "event_search.saved.update", "success", "saved_event_search", saved.SavedSearchId.ToString(), context, new Dictionary<string, object?> { ["visibility"] = saved.Visibility, ["version"] = saved.Version }, cancellationToken);
        return Results.Ok(saved);
    }
    catch (InvalidOperationException ex)
    {
        return Results.Conflict(new { error = ex.Message });
    }
    catch (UnauthorizedAccessException)
    {
        await audit.RecordAsync(operatorId, context.User.Identity?.Name, "event_search.saved.update", "denied", "saved_event_search", savedSearchId.ToString(), context, null, cancellationToken);
        return Results.Forbid();
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["saved_search"] = new[] { ex.Message } });
    }
});

app.MapDelete("/api/v1/events/saved-searches/{savedSearchId:guid}", async Task<IResult> (
    Guid savedSearchId,
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var operatorId = OperatorAuthentication.OperatorId(context.User);
    if (!operatorId.HasValue) return Results.Unauthorized();
    var deleted = await events.DeleteSavedSearchAsync(savedSearchId, operatorId.Value, cancellationToken);
    await audit.RecordAsync(operatorId, context.User.Identity?.Name, "event_search.saved.delete", deleted ? "success" : "denied", "saved_event_search", savedSearchId.ToString(), context, null, cancellationToken);
    return deleted ? Results.Ok(new { status = "deleted" }) : Results.NotFound();
});

app.MapPost("/api/v1/events/export", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var role = OperatorAuthorization.Role(context.User)!;
    var operatorId = OperatorAuthentication.OperatorId(context.User);
    if (!OperatorAuthorization.HasPermission(role, OperatorPermission.ManageOperators))
    {
        await audit.RecordAsync(operatorId, context.User.Identity?.Name, "event_search.export", "denied", "events", null, context, null, cancellationToken);
        return Results.Forbid();
    }

    if (!string.Equals(context.Request.Query["confirm_export"].FirstOrDefault(), "EXPORT", StringComparison.Ordinal))
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["confirm_export"] = new[] { "Type EXPORT to confirm this bounded audited event export." } });
    }

    var query = EventSearchQuery.FromQuery(context.Request.Query, EventSearchQuery.MaxExportLimit);
    if (query.ValidationErrors.Count > 0)
    {
        return Results.ValidationProblem(query.ValidationErrors.GroupBy(item => item.Field).ToDictionary(item => item.Key, item => item.Select(error => error.Message).ToArray()));
    }

    var export = await events.ExportCsvForOperatorAsync(query, role, cancellationToken);
    await audit.RecordAsync(operatorId, context.User.Identity?.Name, "event_search.export", "success", "events", null, context, new Dictionary<string, object?> { ["rows"] = export.Rows, ["limit"] = export.BoundedLimit, ["format"] = "csv" }, cancellationToken);
    context.Response.Headers.ContentDisposition = $"attachment; filename=\"{export.FileName}\"";
    return Results.File(export.Content, "text/csv; charset=utf-8", export.FileName);
});

app.MapGet("/api/v1/storage/accounting", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    IConfiguration configuration,
    IOptions<ManagedRetentionOptions> retentionOptions,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var configuredCapacity = retentionOptions.Value.ManagedCapacityBytes;
    var legacyCapacity = ParseLongOrDefault(configuration["Storage:ManagedCapacityBytes"], configuredCapacity);
    return Results.Ok(await events.GetManagedStorageAccountingAsync(legacyCapacity, cancellationToken, retentionOptions.Value.TargetRetentionDays));
});

app.MapGet("/api/v1/storage/retention/status", async Task<IResult> (
    HttpContext context,
    RetentionRepository retention,
    TokenService tokens,
    IOptions<ManagedRetentionOptions> retentionOptions,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    return Results.Ok(await retention.GetStatusAsync(retentionOptions.Value, cancellationToken));
});

app.MapPost("/api/v1/storage/retention/run", async Task<IResult> (
    HttpContext context,
    RetentionRepository retention,
    TokenService tokens,
    IOptions<ManagedRetentionOptions> retentionOptions,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    RetentionRunRequest request;
    if (context.Request.ContentLength is null or 0)
    {
        request = new RetentionRunRequest();
    }
    else
    {
        request = await JsonSerializer.DeserializeAsync<RetentionRunRequest>(context.Request.Body, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower
        }, cancellationToken) ?? new RetentionRunRequest();
    }

    var result = await retention.RunAsync(retentionOptions.Value, request, cancellationToken);
    return result.Status == "lock_not_acquired" ? Results.Conflict(result) : Results.Ok(result);
});

app.MapGet("/api/v1/source-health", async Task<IResult> (
    HttpContext context,
    SourceHealthRepository sourceHealth,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var agentId = context.Request.Query["agent_id"].FirstOrDefault();
    var targetLevel = ParseCoverageLevelOrDefault(context.Request.Query["target_level"].FirstOrDefault(), WindowsCoverageLevel.L2);
    return Results.Ok(await sourceHealth.SearchAsync(agentId, targetLevel, cancellationToken));
});

app.MapGet("/api/v1/telemetry-coverage", async Task<IResult> (
    HttpContext context,
    TelemetryCoverageRepository telemetryCoverage,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var agentId = context.Request.Query["agent_id"].FirstOrDefault();
    var targetLevel = ParseCoverageLevelOrDefault(context.Request.Query["target_level"].FirstOrDefault(), WindowsCoverageLevel.L2);
    var lookbackHours = ParseIntOrDefault(context.Request.Query["lookback_hours"].FirstOrDefault(), 24);
    return Results.Ok(await telemetryCoverage.AssessAsync(agentId, targetLevel, lookbackHours, cancellationToken));
});

app.MapGet("/api/v1/inventory", async Task<IResult> (
    HttpContext context,
    AssetInventoryRepository inventory,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var agentId = context.Request.Query["agent_id"].FirstOrDefault();
    var snapshotType = context.Request.Query["snapshot_type"].FirstOrDefault();
    return Results.Ok(new { snapshots = await inventory.SearchAsync(agentId, snapshotType, cancellationToken) });
});

app.MapGet("/api/v1/platform/capabilities", (HttpContext context, TokenService tokens, IConfiguration configuration) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    return Results.Ok(new PlatformCapabilitiesResponse { Capabilities = PlatformCapabilityCatalog.All });
});

app.MapGet("/api/v1/alerts", async Task<IResult> (
    HttpContext context,
    AlertRepository alerts,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var status = context.Request.Query["status"].FirstOrDefault();
    var role = OperatorAuthorization.Role(context.User)!;
    return Results.Ok(new { alerts = (await alerts.SearchAlertsAsync(status, cancellationToken)).Select(item => AlertFieldPolicy.Apply(item, role)) });
});

app.MapGet("/api/v1/alerts/{alertId:guid}", async Task<IResult> (
    Guid alertId,
    HttpContext context,
    AlertRepository alerts,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var alert = await alerts.GetAlertAsync(alertId, cancellationToken);
    return alert is null ? Results.NotFound() : Results.Ok(AlertFieldPolicy.Apply(alert, OperatorAuthorization.Role(context.User)!));
});

app.MapGet("/api/v1/graphs", async Task<IResult> (
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var status = context.Request.Query["status"].FirstOrDefault();
    return Results.Ok(new { graphs = await graphs.ListAsync(status, cancellationToken) });
});

app.MapPost("/api/v1/graphs", async Task<IResult> (
    HttpContext context,
    InvestigationGraphCreateRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    try
    {
        return Results.Ok(await graphs.CreateAsync(request, context.User.Identity?.Name ?? "operator", cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["graph"] = new[] { ex.Message } });
    }
});

app.MapGet("/api/v1/graphs/{graphId:guid}", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var detail = await graphs.GetDetailAsync(graphId, cancellationToken);
    return detail is null ? Results.NotFound() : Results.Ok(detail);
});

app.MapPut("/api/v1/graphs/{graphId:guid}", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphUpdateRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    try
    {
        var updated = await graphs.UpdateAsync(graphId, request, context.User.Identity?.Name ?? "operator", cancellationToken);
        return updated is null ? Results.Conflict(new { error = "version_conflict_or_archived" }) : Results.Ok(updated);
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["graph"] = new[] { ex.Message } });
    }
});

app.MapPost("/api/v1/graphs/{graphId:guid}/archive", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var archived = await graphs.ArchiveAsync(graphId, context.User.Identity?.Name ?? "operator", cancellationToken);
    return archived is null ? Results.NotFound() : Results.Ok(archived);
});

app.MapPost("/api/v1/graphs/{graphId:guid}/nodes", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphNodeRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    try
    {
        return Results.Ok(await graphs.AddNodeAsync(graphId, request, context.User.Identity?.Name ?? "operator", cancellationToken));
    }
    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or PostgresException)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["node"] = new[] { ex.Message } });
    }
});

app.MapPost("/api/v1/graphs/{graphId:guid}/edges", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphEdgeRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    try
    {
        return Results.Ok(await graphs.AddEdgeAsync(graphId, request, context.User.Identity?.Name ?? "operator", cancellationToken));
    }
    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or PostgresException)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["edge"] = new[] { ex.Message } });
    }
});

app.MapPost("/api/v1/graphs/{graphId:guid}/proposals", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphProposalRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    try
    {
        return Results.Ok(await graphs.CreateSocAgentProposalAsync(graphId, request.Instruction, context.User.Identity?.Name ?? "operator", cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["proposal"] = new[] { ex.Message } });
    }
});

app.MapPost("/api/v1/graphs/{graphId:guid}/proposals/{proposalId:guid}/apply", async Task<IResult> (
    Guid graphId,
    Guid proposalId,
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var proposal = await graphs.ApplyProposalAsync(graphId, proposalId, context.User.Identity?.Name ?? "operator", cancellationToken);
    return proposal is null ? Results.NotFound() : Results.Ok(proposal);
});

app.MapPost("/api/v1/soc-agent/ask", async Task<IResult> (
    HttpContext context,
    SocAgentAskRequest request,
    SocAgentService socAgent,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    if (string.IsNullOrWhiteSpace(request.Question) || request.Question.Length > 4000)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["question"] = new[] { "Question is required and must be 4000 characters or less." }
        });
    }

    return Results.Ok(await socAgent.AskAsync(request, OperatorAuthorization.Role(context.User)!, cancellationToken));
});

app.MapGet("/api/v1/soc-agent/status", (HttpContext context, SocAgentService socAgent, TokenService tokens, IConfiguration configuration) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    return Results.Ok(socAgent.GetProviderStatus());
});

app.MapGet("/api/v1/soc-agent/sessions", async Task<IResult> (
    HttpContext context,
    SocAgentService socAgent,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    return Results.Ok(new { sessions = await socAgent.GetRecentSessionsAsync(cancellationToken) });
});

app.MapPost("/api/v1/soc-agent/sessions", async Task<IResult> (
    HttpContext context,
    SocAgentSessionCreateRequest request,
    SocAgentService socAgent,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var session = await socAgent.CreateSessionAsync(request, cancellationToken);
    return Results.Ok(session);
});

app.MapGet("/api/v1/soc-agent/sessions/{sessionId:guid}", async Task<IResult> (
    Guid sessionId,
    HttpContext context,
    SocAgentService socAgent,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var detail = await socAgent.GetSessionDetailAsync(sessionId, cancellationToken);
    return detail is null ? Results.NotFound() : Results.Ok(detail);
});

app.MapDelete("/api/v1/soc-agent/sessions/{sessionId:guid}", async Task<IResult> (
    Guid sessionId,
    HttpContext context,
    SocAgentService socAgent,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    var result = await socAgent.DeleteSessionAsync(sessionId, cancellationToken);
    return result.Status switch
    {
        "deleted" => Results.Ok(result),
        "not_found" => Results.NotFound(result),
        "run_active" => Results.Conflict(result),
        _ => Results.Problem("soc-agent chat session deletion could not be completed.")
    };
});

app.MapPost("/api/v1/soc-agent/sessions/{sessionId:guid}/messages", async Task<IResult> (
    Guid sessionId,
    HttpContext context,
    SocAgentChatRequest request,
    SocAgentService socAgent,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    if (string.IsNullOrWhiteSpace(request.Message) || request.Message.Length > 4000)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["message"] = new[] { "Message is required and must be 4000 characters or less." }
        });
    }

    try
    {
        return Results.Ok(await socAgent.SendChatMessageAsync(sessionId, request, OperatorAuthorization.Role(context.User)!, cancellationToken));
    }
    catch (KeyNotFoundException)
    {
        return Results.NotFound();
    }
});

app.MapPost("/soc-agent/live/runs", async Task<IResult> (
    HttpContext context,
    SocAgentLiveRunStartRequest request,
    SocAgentLiveRunCoordinator liveRuns,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Message) || request.Message.Length > 4000)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["message"] = new[] { "Message is required and must be 4000 characters or less." }
        });
    }

    try
    {
        return Results.Ok(await liveRuns.StartRunAsync(request, OperatorAuthorization.Role(context.User)!, cancellationToken));
    }
    catch (KeyNotFoundException)
    {
        return Results.NotFound();
    }
    catch (InvalidOperationException ex)
    {
        return Results.Conflict(new { error = "run_already_active", message = ex.Message });
    }
}).RequireAuthorization("analyst");

app.MapGet("/soc-agent/live/sessions/{sessionId:guid}/active", (
    Guid sessionId,
    SocAgentLiveRunCoordinator liveRuns) => Results.Ok(liveRuns.GetActiveRun(sessionId)))
    .RequireAuthorization("analyst");

app.MapPost("/soc-agent/live/runs/{runId:guid}/cancel", (
    Guid runId,
    SocAgentLiveRunCoordinator liveRuns) =>
{
    var result = liveRuns.CancelRun(runId);
    return result is null ? Results.NotFound() : Results.Ok(result);
}).RequireAuthorization("analyst");

app.MapGet("/soc-agent/live/runs/{runId:guid}/events", async Task<IResult> (
    Guid runId,
    HttpContext context,
    SocAgentLiveRunRegistry liveRuns,
    CancellationToken cancellationToken) =>
{
    if (!liveRuns.TryGetRun(runId, out var state))
    {
        return Results.NotFound();
    }

    var after = ParseLongOrDefault(context.Request.Query["after"].FirstOrDefault(), 0);
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers.Connection = "keep-alive";
    context.Response.ContentType = "text/event-stream; charset=utf-8";

    var snapshot = new SocAgentLiveEvent(
        state.LastSequence,
        "resume_snapshot",
        state.RunId,
        state.SessionId,
        DateTimeOffset.UtcNow,
        new Dictionary<string, object?>
        {
            ["status"] = state.Status,
            ["last_sequence"] = state.LastSequence,
            ["session_id"] = state.SessionId
        });
    await WriteSocAgentLiveEventAsync(context, snapshot, cancellationToken);

    await foreach (var liveEvent in state.ReadEventsAsync(after, cancellationToken))
    {
        await WriteSocAgentLiveEventAsync(context, liveEvent, cancellationToken);
    }

    return Results.Empty;
}).RequireAuthorization("analyst");

app.MapGet("/soc-agent/oauth/start", (HttpContext context, SocAgentSubscriptionOAuthConnectService connect) =>
{
    try
    {
        var authorizationUri = connect.CreateAuthorizationUri(context, "/soc-agent");
        return Results.Redirect(authorizationUri.ToString());
    }
    catch (SocAgentSubscriptionOAuthConnectException ex)
    {
        return Results.Redirect(QueryHelpers.AddQueryString("/soc-agent", "oauth_error", ex.OperatorSafeMessage));
    }
}).RequireAuthorization("analyst");

app.MapGet("/soc-agent/oauth/callback", async Task<IResult> (
    HttpContext context,
    SocAgentSubscriptionOAuthConnectService connect,
    CancellationToken cancellationToken) =>
{
    try
    {
        var result = await connect.CompleteAsync(context, cancellationToken);
        return Results.Redirect(connect.CompleteReturnUrl(result));
    }
    catch (SocAgentSubscriptionOAuthConnectException ex)
    {
        return Results.Redirect(QueryHelpers.AddQueryString("/soc-agent", "oauth_error", ex.OperatorSafeMessage));
    }
}).AllowAnonymous();

app.MapGet("/api/v1/detections/rules", async Task<IResult> (
    HttpContext context,
    AlertRepository alerts,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasOperatorAccess(context))
    {
        return OperatorAccessFailure(context);
    }

    return Results.Ok(new { rules = await alerts.GetRulesAsync(cancellationToken) });
});

app.MapRazorPages();

app.Run();

static IResult OperatorAccessFailure(HttpContext context) => context.User.Identity?.IsAuthenticated == true ? Results.Forbid() : Results.Unauthorized();

static int ParseIntOrDefault(string? value, int fallback)
{
    return int.TryParse(value, out var parsed) ? parsed : fallback;
}

static long ParseLongOrDefault(string? value, long fallback)
{
    return long.TryParse(value, out var parsed) && parsed >= 0 ? parsed : fallback;
}

static WindowsCoverageLevel ParseCoverageLevelOrDefault(string? value, WindowsCoverageLevel fallback)
{
    return Enum.TryParse<WindowsCoverageLevel>(value, ignoreCase: true, out var parsed) ? parsed : fallback;
}

static async Task WriteSocAgentLiveEventAsync(HttpContext context, SocAgentLiveEvent liveEvent, CancellationToken cancellationToken)
{
    await context.Response.WriteAsync($"id: {liveEvent.Sequence}\n", cancellationToken);
    await context.Response.WriteAsync($"event: {liveEvent.Type}\n", cancellationToken);
    await context.Response.WriteAsync("data: ", cancellationToken);
    await JsonSerializer.SerializeAsync(
        context.Response.Body,
        liveEvent,
        new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower
        },
        cancellationToken);
    await context.Response.WriteAsync("\n\n", cancellationToken);
    await context.Response.Body.FlushAsync(cancellationToken);
}

public partial class Program;
