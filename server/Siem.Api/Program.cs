using System.Text.Json;
using System.Text.Json.Serialization;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Api.Mcp;
using Challenger.Siem.Api.Platform;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Api.Storage;
using Challenger.Siem.Contracts.V2;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
var trafficMapReadOnlyDatabase = builder.Configuration.GetValue<bool>($"{TrafficMapOptions.SectionName}:ReadOnlyDatabase");

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

builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton(sp =>
{
    var configuration = sp.GetRequiredService<IConfiguration>();
    var connectionString = configuration.GetConnectionString("SiemDatabase");
    if (string.IsNullOrWhiteSpace(connectionString))
    {
        throw new InvalidOperationException("ConnectionStrings:SiemDatabase is required.");
    }

    if (trafficMapReadOnlyDatabase)
    {
        var readOnly = new NpgsqlConnectionStringBuilder(connectionString);
        var existingOptions = readOnly.Options?.Trim();
        readOnly.Options = string.IsNullOrEmpty(existingOptions)
            ? "-c default_transaction_read_only=on"
            : $"{existingOptions} -c default_transaction_read_only=on";
        connectionString = readOnly.ConnectionString;
    }

    return NpgsqlDataSource.Create(connectionString);
});
builder.Services.AddScoped<AgentRepository>();
builder.Services.AddScoped<SecurityAuditRepository>();
builder.Services.AddScoped<AgentAuthenticator>();
builder.Services.AddScoped<EventRepository>();
builder.Services.AddScoped<NetworkGeographyRepository>();
builder.Services.AddScoped<NetworkActivityRepository>();
builder.Services.AddScoped<ProcessInvestigationRepository>();
builder.Services.AddScoped<RetentionRepository>();
builder.Services.AddScoped<HeartbeatRepository>();
builder.Services.AddScoped<AgentLivenessMonitorRepository>();
builder.Services.AddSingleton<AgentLivenessMonitorState>();
if (!trafficMapReadOnlyDatabase)
    builder.Services.AddHostedService<AgentLivenessMonitorHostedService>();
builder.Services.AddScoped<SourceHealthRepository>();
builder.Services.AddScoped<TelemetryCoverageRepository>();
builder.Services.AddScoped<AssetInventoryRepository>();
builder.Services.AddScoped<AlertRepository>();
builder.Services.AddScoped<CaseRepository>();
builder.Services.AddScoped<DetectionManagementRepository>();
builder.Services.AddScoped<DashboardRepository>();
builder.Services.AddScoped<AdminRepository>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<DetectionEngine>();
builder.Services.AddScoped<IngestionErrorRepository>();
builder.Services.AddScoped<InvestigationGraphRepository>();
builder.Services.AddScoped<ReviewRepository>();
builder.Services.AddSingleton<IpGeolocationService>();
builder.Services.AddHostedService(services => services.GetRequiredService<IpGeolocationService>());
builder.Services.AddHttpClient("traffic-map-geolocation", client => client.DefaultRequestHeaders.Accept.ParseAdd("application/json"));
builder.Services.AddScoped<SiemMcpAccess>();
builder.Services.AddScoped<SiemMcpTools>();
builder.Services.Configure<ReviewOptions>(builder.Configuration.GetSection(ReviewOptions.SectionName));
builder.Services.AddOptions<TrafficMapOptions>()
    .Bind(builder.Configuration.GetSection(TrafficMapOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<TrafficMapOptions>, TrafficMapOptionsValidator>();
builder.Services.AddOptions<ManagedRetentionOptions>()
    .Bind(builder.Configuration.GetSection(ManagedRetentionOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<ManagedRetentionOptions>, ManagedRetentionOptionsValidator>();
if (!trafficMapReadOnlyDatabase)
    builder.Services.AddHostedService<ManagedRetentionHostedService>();
builder.Services
    .AddMcpServer()
    .WithHttpTransport(options =>
    {
        options.Stateless = true;
    })
    .AddAuthorizationFilters()
    .WithTools<SiemMcpTools>(SiemMcpJson.Options)
    .WithResources<SiemMcpResources>()
    .WithPrompts<SiemMcpPrompts>(SiemMcpJson.Options);
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = ServiceAuthentication.Scheme;
        options.DefaultChallengeScheme = ServiceAuthentication.Scheme;
    })
    .AddScheme<AuthenticationSchemeOptions, ServiceBearerHandler>(ServiceAuthentication.Scheme, null);
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("service", policy => policy.RequireAuthenticatedUser());
});

var app = builder.Build();

StartupConfigurationValidator.ValidateRequiredConfiguration(app.Configuration);

app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers.TryAdd("X-Content-Type-Options", "nosniff");
    if (trafficMapReadOnlyDatabase)
        context.Response.Headers.TryAdd("X-Challenger-Database-Mode", "read-only");
    if (!app.Environment.IsDevelopment() && !context.Request.IsHttps)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { error = "https_required" });
        return;
    }

    await next();
});
app.Use(async (context, next) =>
{
    if (trafficMapReadOnlyDatabase
        && context.Request.Path.StartsWithSegments("/api/v2")
        && !HttpMethods.IsGet(context.Request.Method)
        && !HttpMethods.IsHead(context.Request.Method))
    {
        context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
        context.Response.Headers.Allow = "GET, HEAD";
        await context.Response.WriteAsJsonAsync(new { error = "database_read_only" });
        return;
    }

    await next();
});
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/ui"))
    {
        var trafficMap = context.RequestServices.GetRequiredService<IOptions<TrafficMapOptions>>().Value;
        if (!trafficMap.Enabled)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsJsonAsync(new { error = "traffic_map_disabled" });
            return;
        }
        if (!LoopbackTrafficMapAccess.CanServeUi(context, trafficMap))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsJsonAsync(new { error = "traffic_map_direct_loopback_required" });
            return;
        }
        var expandedTileUrl = trafficMap.Map.TileUrl.Replace("{z}", "0", StringComparison.Ordinal)
            .Replace("{x}", "0", StringComparison.Ordinal)
            .Replace("{y}", "0", StringComparison.Ordinal);
        var tileOrigin = Uri.TryCreate(expandedTileUrl, UriKind.Absolute, out var tileUri)
            ? tileUri.GetLeftPart(UriPartial.Authority)
            : "https://tile.openstreetmap.org";
        context.Response.Headers.ContentSecurityPolicy = $"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: {tileOrigin}; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        context.Response.Headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()";
    }
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/mcp"))
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        var authorization = context.Request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            || context.User.Identity?.IsAuthenticated != true)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = "Bearer";
            await context.Response.WriteAsJsonAsync(new { error = "mcp_service_bearer_required" });
            return;
        }
    }
    await next();
});
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? string.Empty;
    var isServiceApi = path.StartsWith("/api/v2/", StringComparison.Ordinal)
        && !path.StartsWith("/api/v2/agents/", StringComparison.Ordinal)
        && !path.StartsWith("/api/v2/ingest/", StringComparison.Ordinal);
    if (isServiceApi && !trafficMapReadOnlyDatabase)
    {
        var audit = context.RequestServices.GetRequiredService<SecurityAuditRepository>();
        var trafficMap = context.RequestServices.GetRequiredService<IOptions<TrafficMapOptions>>().Value;
        var authenticated = context.User.Identity?.IsAuthenticated == true;
        var tokenAccess = context.RequestServices.GetRequiredService<TokenService>().HasServiceAccess(context);
        var loopbackAccess = LoopbackTrafficMapAccess.CanImplyAuthentication(context, trafficMap);
        var allowed = authenticated && (tokenAccess || loopbackAccess);
        await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name ?? ServiceAuthentication.PrincipalName,
            "service.api_access", allowed ? "success" : "denied", "route", path, context,
            new Dictionary<string,object?>
            {
                ["method"] = context.Request.Method,
                ["authentication_mode"] = loopbackAccess ? "direct_loopback" : "service_bearer"
            }, context.RequestAborted);
    }
    await next();
});
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapGet("/api/v2/network/geography", async Task<IResult> (
    HttpContext context,
    NetworkGeographyRepository geography,
    TokenService tokens,
    IOptions<TrafficMapOptions> trafficMap,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)
        && !LoopbackTrafficMapAccess.CanImplyAuthentication(context, trafficMap.Value))
        return ServiceAccessFailure(context);
    if (!trafficMap.Value.Enabled) return Results.NotFound(new { error = "traffic_map_disabled" });

    var query = NetworkGeographyQuery.FromQuery(context.Request.Query);
    if (query.ValidationErrors.Count > 0)
    {
        return Results.ValidationProblem(query.ValidationErrors
            .GroupBy(item => item.Field)
            .ToDictionary(item => item.Key, item => item.Select(error => error.Message).ToArray()));
    }
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers.Pragma = "no-cache";
    return Results.Ok(await geography.GetAsync(query, cancellationToken));
});

app.MapGet("/api/v2/network/geography/events", async Task<IResult> (
    HttpContext context,
    NetworkGeographyRepository geography,
    TokenService tokens,
    IOptions<TrafficMapOptions> trafficMap,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)
        && !LoopbackTrafficMapAccess.CanImplyAuthentication(context, trafficMap.Value))
        return ServiceAccessFailure(context);
    if (!trafficMap.Value.Enabled) return Results.NotFound(new { error = "traffic_map_disabled" });

    var query = NetworkGeographyEvidenceQuery.FromQuery(context.Request.Query);
    if (query.ValidationErrors.Count > 0)
    {
        return Results.ValidationProblem(query.ValidationErrors
            .GroupBy(item => item.Field)
            .ToDictionary(item => item.Key, item => item.Select(error => error.Message).ToArray()));
    }
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers.Pragma = "no-cache";
    return Results.Ok(await geography.GetEvidenceAsync(query, cancellationToken));
});

app.MapGet("/api/v2/network/activity", async Task<IResult> (
    HttpContext context,
    NetworkActivityRepository activity,
    TokenService tokens,
    IOptions<TrafficMapOptions> trafficMap,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    var query = NetworkActivityQuery.FromQuery(context.Request.Query);
    if (query.ValidationErrors.Count > 0)
    {
        return Results.ValidationProblem(query.ValidationErrors
            .GroupBy(item => item.Field)
            .ToDictionary(item => item.Key, item => item.Select(error => error.Message).ToArray()));
    }
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers.Pragma = "no-cache";
    return Results.Ok(await activity.SearchAsync(query, trafficMap.Value.Enabled, cancellationToken));
});

app.MapPost("/api/v2/agents/register", async Task<IResult> (
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

app.MapPost("/api/v2/agents/heartbeat", async Task<IResult> (
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

app.MapPost("/api/v2/agents/inventory", async Task<IResult> (
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

app.MapPost("/api/v2/ingest/events", async Task<IResult> (
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

    var maxEventsPerBatch = ParseIntOrDefault(configuration["Ingestion:MaxEventsPerBatch"], ContractLimits.MaxIngestEventsPerBatch);
    var validationErrors = RequestValidation.ValidateBatch(request, maxEventsPerBatch);
    if (validationErrors.Count > 0)
    {
        await ingestionErrors.RecordValidationErrorsAsync(request, validationErrors, cancellationToken);
        return Results.ValidationProblem(validationErrors);
    }

    var result = await events.StoreEventsAsync(request, cancellationToken);
    var detectionCandidates = result.AcceptedEventIds.Concat(result.DuplicateEventIds);
    var storedDetectionEvents = await events.LoadStoredEventsAsync(request.AgentId, detectionCandidates, cancellationToken);
    var potentialDetectionEvents = storedDetectionEvents
        .Where(detectionEngine.HasPotentialLinuxDetection)
        .ToArray();
    await alerts.RunLinuxDetectionsAsync(potentialDetectionEvents, detectionEngine, cancellationToken);
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

app.MapGet("/api/v2/events", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var query = EventSearchQuery.FromQuery(context.Request.Query);
    if (query.ValidationErrors.Count > 0)
    {
        return Results.ValidationProblem(query.ValidationErrors.GroupBy(item => item.Field).ToDictionary(item => item.Key, item => item.Select(error => error.Message).ToArray()));
    }

    var page = await events.SearchEventsPageForServiceAsync(query, ServiceAuthorization.Role(context.User)!, cancellationToken);
    return Results.Ok(new EventSearchResponse
    {
        Events = page.Events,
        Page = page.Page,
        ActiveFilters = page.ActiveFilters,
        ResultScope = page.ResultScope,
        Redaction = page.RedactionNotice
    });
});

app.MapGet("/api/v2/events/timeline", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var query = EventSearchQuery.FromQuery(context.Request.Query);
    if (query.ValidationErrors.Count > 0)
    {
        return Results.ValidationProblem(query.ValidationErrors.GroupBy(item => item.Field).ToDictionary(item => item.Key, item => item.Select(error => error.Message).ToArray()));
    }

    var timeline = await events.GetTimelineAsync(query, ServiceAuthorization.Role(context.User)!, cancellationToken);
    return Results.Ok(new EventTimelineResponse
    {
        Buckets = timeline.Buckets,
        BucketSeconds = timeline.BucketSeconds
    });
});

app.MapGet("/api/v2/events/saved-searches", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    return Results.Ok(new { saved_searches = await events.ListSavedSearchesAsync(ServiceAuthentication.ServiceId, ServiceRoles.Service, cancellationToken) });
});

app.MapPost("/api/v2/events/saved-searches", async Task<IResult> (
    SavedEventSearchRequest request,
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var serviceId = ServiceAuthentication.ServiceId;
    try
    {
        var saved = await events.SaveSearchAsync(request, serviceId, ServiceAuthentication.PrincipalName, true, cancellationToken);
        await audit.RecordAsync(serviceId, context.User.Identity?.Name, "event_search.saved.create", "success", "saved_event_search", saved.SavedSearchId.ToString(), context, new Dictionary<string, object?> { ["visibility"] = saved.Visibility, ["version"] = saved.Version }, cancellationToken);
        return Results.Ok(saved);
    }
    catch (UnauthorizedAccessException)
    {
        await audit.RecordAsync(serviceId, context.User.Identity?.Name, "event_search.saved.create", "denied", "saved_event_search", null, context, null, cancellationToken);
        return Results.Forbid();
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["saved_search"] = new[] { ex.Message } });
    }
});

app.MapPut("/api/v2/events/saved-searches/{savedSearchId:guid}", async Task<IResult> (
    Guid savedSearchId,
    SavedEventSearchRequest request,
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var serviceId = ServiceAuthentication.ServiceId;
    try
    {
        var saved = await events.SaveSearchAsync(request, serviceId, ServiceAuthentication.PrincipalName, true, cancellationToken, savedSearchId);
        await audit.RecordAsync(serviceId, context.User.Identity?.Name, "event_search.saved.update", "success", "saved_event_search", saved.SavedSearchId.ToString(), context, new Dictionary<string, object?> { ["visibility"] = saved.Visibility, ["version"] = saved.Version }, cancellationToken);
        return Results.Ok(saved);
    }
    catch (InvalidOperationException ex)
    {
        return Results.Conflict(new { error = ex.Message });
    }
    catch (UnauthorizedAccessException)
    {
        await audit.RecordAsync(serviceId, context.User.Identity?.Name, "event_search.saved.update", "denied", "saved_event_search", savedSearchId.ToString(), context, null, cancellationToken);
        return Results.Forbid();
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["saved_search"] = new[] { ex.Message } });
    }
});

app.MapDelete("/api/v2/events/saved-searches/{savedSearchId:guid}", async Task<IResult> (
    Guid savedSearchId,
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var serviceId = ServiceAuthentication.ServiceId;
    var deleted = await events.DeleteSavedSearchAsync(savedSearchId, serviceId, cancellationToken);
    await audit.RecordAsync(serviceId, context.User.Identity?.Name, "event_search.saved.delete", deleted ? "success" : "denied", "saved_event_search", savedSearchId.ToString(), context, null, cancellationToken);
    return deleted ? Results.Ok(new { status = "deleted" }) : Results.NotFound();
});

app.MapPost("/api/v2/events/export", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var role = ServiceAuthorization.Role(context.User)!;
    var serviceId = ServiceAuthentication.ServiceId;
    if (!ServiceAuthorization.HasPermission(role, ServicePermission.ExportEvents))
    {
        await audit.RecordAsync(serviceId, context.User.Identity?.Name, "event_search.export", "denied", "events", null, context, null, cancellationToken);
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

    var export = await events.ExportCsvForServiceAsync(query, role, cancellationToken);
    await audit.RecordAsync(serviceId, context.User.Identity?.Name, "event_search.export", "success", "events", null, context, new Dictionary<string, object?> { ["rows"] = export.Rows, ["limit"] = export.BoundedLimit, ["format"] = "csv" }, cancellationToken);
    context.Response.Headers.ContentDisposition = $"attachment; filename=\"{export.FileName}\"";
    return Results.File(export.Content, "text/csv; charset=utf-8", export.FileName);
});

app.MapGet("/api/v2/storage/accounting", async Task<IResult> (
    HttpContext context,
    EventRepository events,
    TokenService tokens,
    IConfiguration configuration,
    IOptions<ManagedRetentionOptions> retentionOptions,
    AdminRepository admin,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var effectiveOptions = await admin.GetEffectiveRetentionOptionsAsync(retentionOptions.Value, cancellationToken);
    var legacyCapacity = ParseLongOrDefault(configuration["Storage:ManagedCapacityBytes"], effectiveOptions.ManagedCapacityBytes);
    return Results.Ok(await events.GetManagedStorageAccountingAsync(legacyCapacity, cancellationToken, effectiveOptions.TargetRetentionDays));
});

app.MapGet("/api/v2/storage/retention/status", async Task<IResult> (
    HttpContext context,
    RetentionRepository retention,
    TokenService tokens,
    IOptions<ManagedRetentionOptions> retentionOptions,
    AdminRepository admin,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var effectiveOptions = await admin.GetEffectiveRetentionOptionsAsync(retentionOptions.Value, cancellationToken);
    return Results.Ok(await retention.GetStatusAsync(effectiveOptions, cancellationToken));
});

app.MapPost("/api/v2/storage/retention/run", async Task<IResult> (
    HttpContext context,
    RetentionRepository retention,
    TokenService tokens,
    IOptions<ManagedRetentionOptions> retentionOptions,
    AdminRepository admin,
    SecurityAuditRepository audit,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    RetentionRunRequest request;
    if (context.Request.ContentLength == 0)
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

    if (!request.HasRequiredManualConfirmation())
    {
        await audit.RecordAsync(
            ServiceAuthentication.ServiceId,
            context.User.Identity?.Name,
            "storage.retention.run",
            "denied",
            "managed_telemetry",
            null,
            context,
            new Dictionary<string, object?>
            {
                ["mode"] = "execute",
                ["reason"] = "confirmation_missing",
                ["emergency"] = request.Emergency,
                ["max_batches"] = request.MaxBatches
            },
            cancellationToken);
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["confirm_impact"] = new[] { $"Type {RetentionRunRequest.ExecutionConfirmation} to execute managed telemetry deletion." }
        });
    }

    var effectiveOptions = await admin.GetEffectiveRetentionOptionsAsync(retentionOptions.Value, cancellationToken);
    var result = await retention.RunAsync(effectiveOptions, request, cancellationToken);
    await audit.RecordAsync(
        ServiceAuthentication.ServiceId,
        context.User.Identity?.Name,
        "storage.retention.run",
        result.Status is "completed" or "disabled" ? "success" : "failure",
        "managed_telemetry",
        result.RunId.ToString(),
        context,
        new Dictionary<string, object?>
        {
            ["mode"] = result.Mode,
            ["status"] = result.Status,
            ["trigger"] = result.Trigger,
            ["emergency"] = request.Emergency,
            ["max_batches"] = request.MaxBatches,
            ["removed_rows"] = result.RemovedRows,
            ["removed_event_rows"] = result.RemovedEventRows,
            ["lock_acquired"] = result.AdvisoryLockAcquired
        },
        cancellationToken);
    return result.Status == "lock_not_acquired" ? Results.Conflict(result) : Results.Ok(result);
});

app.MapGet("/api/v2/source-health", async Task<IResult> (
    HttpContext context,
    SourceHealthRepository sourceHealth,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var agentId = context.Request.Query["agent_id"].FirstOrDefault();
    var targetLevel = ParseCoverageLevelOrDefault(context.Request.Query["target_level"].FirstOrDefault(), CoverageLevel.L2);
    return Results.Ok(await sourceHealth.SearchAsync(agentId, targetLevel, cancellationToken));
});

app.MapGet("/api/v2/telemetry-coverage", async Task<IResult> (
    HttpContext context,
    TelemetryCoverageRepository telemetryCoverage,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var agentId = context.Request.Query["agent_id"].FirstOrDefault();
    var targetLevel = ParseCoverageLevelOrDefault(context.Request.Query["target_level"].FirstOrDefault(), CoverageLevel.L2);
    var lookbackHours = ParseIntOrDefault(context.Request.Query["lookback_hours"].FirstOrDefault(), 24);
    return Results.Ok(await telemetryCoverage.AssessAsync(agentId, targetLevel, lookbackHours, cancellationToken));
});

app.MapGet("/api/v2/inventory", async Task<IResult> (
    HttpContext context,
    AssetInventoryRepository inventory,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var agentId = context.Request.Query["agent_id"].FirstOrDefault();
    var snapshotType = context.Request.Query["snapshot_type"].FirstOrDefault();
    var generationId = context.Request.Query["generation_id"].FirstOrDefault();
    var pageText = context.Request.Query["page_index"].FirstOrDefault();
    if (generationId is { Length: > 0 } && (generationId.Length > 64
        || generationId.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["generation_id"] = ["Generation ID must be a bounded safe token."] });
    if (pageText is not null && (!int.TryParse(pageText, out var parsedPage) || parsedPage is < 1 or > AssetInventoryPaging.MaxPagesPerSource))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["page_index"] = ["Page index must be from 1 through 32."] });
    int? pageIndex = pageText is null ? null : int.Parse(pageText, System.Globalization.CultureInfo.InvariantCulture);
    var snapshots = await inventory.SearchAsync(agentId, snapshotType, generationId, pageIndex, cancellationToken);
    var generationPages = pageIndex.HasValue
        ? await inventory.SearchAsync(agentId, snapshotType, generationId, null, cancellationToken)
        : snapshots;
    var generations = generationPages.GroupBy(AssetInventoryPaging.GenerationKey, StringComparer.Ordinal)
        .Select(group => AssetInventoryPaging.Status(group.ToArray())).ToArray();
    return Results.Ok(new
    {
        snapshots,
        generation_count = generations.Length,
        complete_generation_count = generations.Count(status => status.Complete),
        incomplete_generation_count = generations.Count(status => !status.Complete),
        received_page_count = generationPages.Count,
        declared_page_count = generations.Sum(status => status.PageCount)
    });
});

app.MapGet("/api/v2/platform/capabilities", (HttpContext context, TokenService tokens, IConfiguration configuration) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    return Results.Ok(new PlatformCapabilitiesResponse { Capabilities = PlatformCapabilityCatalog.All });
});

app.MapGet("/api/v2/alerts", async Task<IResult> (
    HttpContext context,
    AlertRepository alerts,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var status = context.Request.Query["status"].FirstOrDefault();
    var role = ServiceAuthorization.Role(context.User)!;
    return Results.Ok(new { alerts = (await alerts.SearchAlertsAsync(status, cancellationToken)).Select(item => ServiceAlertPolicy.Apply(item, role)) });
});

app.MapGet("/api/v2/alerts/{alertId:guid}", async Task<IResult> (
    Guid alertId,
    HttpContext context,
    AlertRepository alerts,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var alert = await alerts.GetAlertAsync(alertId, cancellationToken);
    return alert is null ? Results.NotFound() : Results.Ok(ServiceAlertPolicy.Apply(alert, ServiceAuthorization.Role(context.User)!));
});

app.MapPost("/api/v2/alerts/{alertId:guid}/assign", async Task<IResult> (Guid alertId, AlertMutationRequest request, HttpContext context, AlertRepository alerts, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try
    {
        var result = await alerts.AssignAsync(alertId, request, ServiceAuthentication.PrincipalName, cancellationToken);
        await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "alert.assign", result is null ? "failure" : "success", "alert", alertId.ToString(), context, new Dictionary<string, object?> { ["expected_version"] = request.ExpectedVersion }, cancellationToken);
        return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(ServiceAlertPolicy.Apply(result, ServiceAuthorization.Role(context.User)!));
    }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["alert"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/alerts/{alertId:guid}/acknowledge", async Task<IResult> (Guid alertId, AlertMutationRequest request, HttpContext context, AlertRepository alerts, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try
    {
        var result = await alerts.AcknowledgeAsync(alertId, request, ServiceAuthentication.PrincipalName, cancellationToken);
        await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "alert.acknowledge", result is null ? "failure" : "success", "alert", alertId.ToString(), context, new Dictionary<string, object?> { ["expected_version"] = request.ExpectedVersion }, cancellationToken);
        return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(ServiceAlertPolicy.Apply(result, ServiceAuthorization.Role(context.User)!));
    }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["alert"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/alerts/{alertId:guid}/status", async Task<IResult> (Guid alertId, AlertMutationRequest request, HttpContext context, AlertRepository alerts, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try
    {
        var result = await alerts.SetStatusAsync(alertId, request, ServiceAuthentication.PrincipalName, cancellationToken);
        await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "alert.status", result is null ? "failure" : "success", "alert", alertId.ToString(), context, new Dictionary<string, object?> { ["status"] = request.Status, ["expected_version"] = request.ExpectedVersion }, cancellationToken);
        return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(ServiceAlertPolicy.Apply(result, ServiceAuthorization.Role(context.User)!));
    }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["alert"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/alerts/{alertId:guid}/suppress", async Task<IResult> (Guid alertId, AlertMutationRequest request, HttpContext context, AlertRepository alerts, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try
    {
        var result = await alerts.SuppressAsync(alertId, request, ServiceAuthentication.PrincipalName, cancellationToken);
        await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "alert.suppress", result is null ? "failure" : "success", "alert", alertId.ToString(), context, new Dictionary<string, object?> { ["expected_version"] = request.ExpectedVersion, ["has_expiry"] = request.SuppressedUntil.HasValue }, cancellationToken);
        return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(ServiceAlertPolicy.Apply(result, ServiceAuthorization.Role(context.User)!));
    }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["alert"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/alerts/{alertId:guid}/close", async Task<IResult> (Guid alertId, AlertMutationRequest request, HttpContext context, AlertRepository alerts, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try
    {
        var result = await alerts.CloseAsync(alertId, request, ServiceAuthentication.PrincipalName, cancellationToken);
        await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "alert.close", result is null ? "failure" : "success", "alert", alertId.ToString(), context, new Dictionary<string, object?> { ["disposition"] = request.Disposition, ["expected_version"] = request.ExpectedVersion }, cancellationToken);
        return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(ServiceAlertPolicy.Apply(result, ServiceAuthorization.Role(context.User)!));
    }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["alert"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/alerts/{alertId:guid}/reopen", async Task<IResult> (Guid alertId, AlertMutationRequest request, HttpContext context, AlertRepository alerts, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try
    {
        var result = await alerts.ReopenAsync(alertId, request, ServiceAuthentication.PrincipalName, cancellationToken);
        await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "alert.reopen", result is null ? "failure" : "success", "alert", alertId.ToString(), context, new Dictionary<string, object?> { ["expected_version"] = request.ExpectedVersion }, cancellationToken);
        return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(ServiceAlertPolicy.Apply(result, ServiceAuthorization.Role(context.User)!));
    }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["alert"] = new[] { ex.Message } }); }
});

app.MapGet("/api/v2/cases", async Task<IResult> (HttpContext context, CaseRepository cases, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    return Results.Ok(new { cases = await cases.ListAsync(context.Request.Query["status"].FirstOrDefault(), context.Request.Query["owner"].FirstOrDefault(), cancellationToken) });
});

app.MapPost("/api/v2/cases", async Task<IResult> (CaseCreateRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try
    {
        var created = await cases.CreateAsync(request, ServiceAuthentication.PrincipalName, cancellationToken);
        await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.create", "success", "case", created.CaseId.ToString(), context, new Dictionary<string, object?> { ["severity"] = created.Severity, ["priority"] = created.Priority, ["linked_alerts"] = request.AlertIds.Count }, cancellationToken);
        return Results.Ok(created);
    }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapGet("/api/v2/cases/{caseId:guid}", async Task<IResult> (Guid caseId, HttpContext context, CaseRepository cases, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    var detail = await cases.GetAsync(caseId, cancellationToken);
    return detail is null ? Results.NotFound() : Results.Ok(detail);
});

app.MapPut("/api/v2/cases/{caseId:guid}", async Task<IResult> (Guid caseId, CaseMutationRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.UpdateAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.update", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["expected_version"] = request.ExpectedVersion }, cancellationToken); return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/status", async Task<IResult> (Guid caseId, CaseMutationRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.SetStatusAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.status", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["status"] = request.Status, ["expected_version"] = request.ExpectedVersion }, cancellationToken); return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/assign", async Task<IResult> (Guid caseId, CaseMutationRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.AssignAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.assign", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["expected_version"] = request.ExpectedVersion }, cancellationToken); return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/close", async Task<IResult> (Guid caseId, CaseMutationRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.CloseAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.close", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["disposition"] = request.Disposition, ["coverage_gap_acknowledged"] = request.CoverageGapAcknowledged, ["expected_version"] = request.ExpectedVersion }, cancellationToken); return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/reopen", async Task<IResult> (Guid caseId, CaseMutationRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.ReopenAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.reopen", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["expected_version"] = request.ExpectedVersion }, cancellationToken); return result is null ? Results.Conflict(new { error = "version_conflict_or_missing" }) : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/notes", async Task<IResult> (Guid caseId, CaseNoteRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.AddNoteAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.note", result is null ? "failure" : "success", "case", caseId.ToString(), context, null, cancellationToken); return result is null ? Results.NotFound() : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/alerts", async Task<IResult> (Guid caseId, CaseAlertRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.LinkAlertAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.link_alert", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["alert_id"] = request.AlertId }, cancellationToken); return result is null ? Results.NotFound() : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/entities", async Task<IResult> (Guid caseId, CaseEntityRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.LinkEntityAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.link_entity", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["entity_type"] = request.EntityType }, cancellationToken); return result is null ? Results.NotFound() : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/graphs", async Task<IResult> (Guid caseId, CaseGraphRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.LinkGraphAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.link_graph", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["graph_id"] = request.GraphId }, cancellationToken); return result is null ? Results.NotFound() : Results.Ok(result); }
    catch (Exception ex) when (ex is ArgumentException or PostgresException) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapPost("/api/v2/cases/{caseId:guid}/evidence", async Task<IResult> (Guid caseId, CaseEvidenceRequest request, HttpContext context, CaseRepository cases, SecurityAuditRepository audit, TokenService tokens, CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context)) return ServiceAccessFailure(context);
    try { var result = await cases.LinkEvidenceAsync(caseId, request, ServiceAuthentication.PrincipalName, cancellationToken); await audit.RecordAsync(ServiceAuthentication.ServiceId, context.User.Identity?.Name, "case.link_evidence", result is null ? "failure" : "success", "case", caseId.ToString(), context, new Dictionary<string, object?> { ["agent_id"] = request.AgentId, ["event_id"] = request.EventId }, cancellationToken); return result is null ? Results.NotFound() : Results.Ok(result); }
    catch (ArgumentException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["case"] = new[] { ex.Message } }); }
});

app.MapGet("/api/v2/graphs", async Task<IResult> (
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var status = context.Request.Query["status"].FirstOrDefault();
    return Results.Ok(new { graphs = await graphs.ListAsync(status, cancellationToken) });
});

app.MapPost("/api/v2/graphs", async Task<IResult> (
    HttpContext context,
    InvestigationGraphCreateRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    try
    {
        return Results.Ok(await graphs.CreateAsync(request, ServiceAuthentication.PrincipalName, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["graph"] = new[] { ex.Message } });
    }
});

app.MapGet("/api/v2/graphs/{graphId:guid}", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var detail = await graphs.GetDetailAsync(graphId, cancellationToken);
    return detail is null ? Results.NotFound() : Results.Ok(detail);
});

app.MapPut("/api/v2/graphs/{graphId:guid}", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphUpdateRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    try
    {
        var updated = await graphs.UpdateAsync(graphId, request, ServiceAuthentication.PrincipalName, cancellationToken);
        return updated is null ? Results.Conflict(new { error = "version_conflict_or_archived" }) : Results.Ok(updated);
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["graph"] = new[] { ex.Message } });
    }
});

app.MapPost("/api/v2/graphs/{graphId:guid}/archive", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var archived = await graphs.ArchiveAsync(graphId, ServiceAuthentication.PrincipalName, cancellationToken);
    return archived is null ? Results.NotFound() : Results.Ok(archived);
});

app.MapPost("/api/v2/graphs/{graphId:guid}/nodes", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphNodeRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    try
    {
        return Results.Ok(await graphs.AddNodeAsync(graphId, request, ServiceAuthentication.PrincipalName, cancellationToken));
    }
    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or PostgresException)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["node"] = new[] { ex.Message } });
    }
});

app.MapPost("/api/v2/graphs/{graphId:guid}/edges", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphEdgeRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    try
    {
        return Results.Ok(await graphs.AddEdgeAsync(graphId, request, ServiceAuthentication.PrincipalName, cancellationToken));
    }
    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or PostgresException)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["edge"] = new[] { ex.Message } });
    }
});

app.MapPost("/api/v2/graphs/{graphId:guid}/proposals", async Task<IResult> (
    Guid graphId,
    HttpContext context,
    InvestigationGraphProposalRequest request,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    try
    {
        return Results.Ok(await graphs.CreateServiceProposalAsync(graphId, request.Instruction, ServiceAuthentication.PrincipalName, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["proposal"] = new[] { ex.Message } });
    }
});

app.MapPost("/api/v2/graphs/{graphId:guid}/proposals/{proposalId:guid}/apply", async Task<IResult> (
    Guid graphId,
    Guid proposalId,
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var proposal = await graphs.ApplyProposalAsync(graphId, proposalId, ServiceAuthentication.PrincipalName, cancellationToken);
    return proposal is null ? Results.NotFound() : Results.Ok(proposal);
});

app.MapGet("/api/v2/detections/rules", async Task<IResult> (
    HttpContext context,
    AlertRepository alerts,
    DetectionManagementRepository detectionManagement,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var rules = await alerts.GetRulesAsync(cancellationToken);
    var managedRules = await detectionManagement.ListAsync(rules, cancellationToken);
    return Results.Ok(new { rules, managed_rules = managedRules });
});

app.MapPut("/api/v2/detections/rules/{ruleId}/{version:int}/settings", async Task<IResult> (
    string ruleId,
    int version,
    DetectionRuleSettingsRequest request,
    HttpContext context,
    AlertRepository alerts,
    DetectionManagementRepository detectionManagement,
    SecurityAuditRepository audit,
    TokenService tokens,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    try
    {
        var rules = await alerts.GetRulesAsync(cancellationToken);
        var updated = await detectionManagement.UpdateSettingsAsync(rules, ruleId, version, request, ServiceAuthentication.PrincipalName, context, audit, cancellationToken);
        return updated is null ? Results.Conflict(new { error = "version_conflict" }) : Results.Ok(updated);
    }
    catch (KeyNotFoundException)
    {
        return Results.NotFound();
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["settings"] = new[] { ex.Message } });
    }
});

app.MapGet("/api/v2/dashboards/summary", async Task<IResult> (
    HttpContext context,
    DashboardRepository dashboards,
    TokenService tokens,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    var hours = ParseIntOrDefault(context.Request.Query["time_range_hours"].FirstOrDefault(), 24);
    return Results.Ok(await dashboards.GetAggregationsAsync(hours, cancellationToken));
});

app.MapGet("/api/v2/admin/overview", async Task<IResult> (
    HttpContext context,
    AdminRepository admin,
    TokenService tokens,
    IOptions<ManagedRetentionOptions> retentionOptions,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    return Results.Ok(await admin.GetOverviewAsync(retentionOptions.Value, cancellationToken));
});

app.MapPut("/api/v2/admin/settings", async Task<IResult> (
    AdminConfigSettingRequest request,
    HttpContext context,
    AdminRepository admin,
    SecurityAuditRepository audit,
    TokenService tokens,
    IOptions<ManagedRetentionOptions> retentionOptions,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    try
    {
        var updated = await admin.UpdateSettingAsync(request, ServiceAuthentication.PrincipalName, context, audit, retentionOptions.Value, cancellationToken);
        return updated is null ? Results.Conflict(new { error = "version_conflict" }) : Results.Ok(updated);
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["setting"] = new[] { ex.Message } });
    }
});

app.MapPut("/api/v2/admin/sources", async Task<IResult> (
    AdminSourceSettingRequest request,
    HttpContext context,
    AdminRepository admin,
    SecurityAuditRepository audit,
    TokenService tokens,
    CancellationToken cancellationToken) =>
{
    if (!tokens.HasServiceAccess(context))
    {
        return ServiceAccessFailure(context);
    }

    try
    {
        var updated = await admin.UpdateSourceSettingAsync(request, ServiceAuthentication.PrincipalName, context, audit, cancellationToken);
        return updated is null ? Results.Conflict(new { error = "version_conflict" }) : Results.Ok(updated);
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["source"] = new[] { ex.Message } });
    }
});

app.MapFallbackToFile("/ui/{*path:nonfile}", "ui/index.html");

app.MapMcp("/mcp").RequireAuthorization("service");

app.Run();

static IResult ServiceAccessFailure(HttpContext context) => context.User.Identity?.IsAuthenticated == true ? Results.Forbid() : Results.Unauthorized();

static int ParseIntOrDefault(string? value, int fallback)
{
    return int.TryParse(value, out var parsed) ? parsed : fallback;
}

static long ParseLongOrDefault(string? value, long fallback)
{
    return long.TryParse(value, out var parsed) && parsed >= 0 ? parsed : fallback;
}

static CoverageLevel ParseCoverageLevelOrDefault(string? value, CoverageLevel fallback)
{
    return Enum.TryParse<CoverageLevel>(value, ignoreCase: true, out var parsed) ? parsed : fallback;
}

public partial class Program;
