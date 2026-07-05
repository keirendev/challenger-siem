using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Api.SocAgent;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Authentication.Cookies;
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
});

builder.Services.AddSingleton<TokenService>();
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
builder.Services.AddScoped<AgentAuthenticator>();
builder.Services.AddScoped<EventRepository>();
builder.Services.AddScoped<HeartbeatRepository>();
builder.Services.AddScoped<SourceHealthRepository>();
builder.Services.AddScoped<AssetInventoryRepository>();
builder.Services.AddScoped<AlertRepository>();
builder.Services.AddScoped<SocAgentRepository>();
builder.Services.AddScoped<SocAgentProviderStatusService>();
builder.Services.AddScoped<SocAgentService>();
builder.Services.AddSingleton<DetectionEngine>();
builder.Services.AddScoped<IngestionErrorRepository>();
builder.Services.AddScoped<InvestigationGraphRepository>();
builder.Services.AddScoped<ReviewRepository>();
builder.Services.Configure<ReviewOptions>(builder.Configuration.GetSection(ReviewOptions.SectionName));
builder.Services.Configure<SocAgentOptions>(builder.Configuration.GetSection(SocAgentOptions.SectionName));
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/");
    options.Conventions.AllowAnonymousToPage("/Login");
});
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.AccessDeniedPath = "/login";
        options.Cookie.Name = ".ChallengerSiem.Review";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });
builder.Services.AddAuthorization();

var app = builder.Build();

StartupConfigurationValidator.ValidateRequiredConfiguration(app.Configuration);

app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
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
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

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

app.MapPost("/api/v1/ingest/events", async Task<IResult> (
    HttpContext context,
    IngestBatchRequest request,
    AgentAuthenticator authenticator,
    EventRepository events,
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    var query = EventSearchQuery.FromQuery(context.Request.Query);
    var results = await events.SearchEventsAsync(query, cancellationToken);
    return Results.Ok(new EventSearchResponse { Events = results });
});

app.MapGet("/api/v1/source-health", async Task<IResult> (
    HttpContext context,
    SourceHealthRepository sourceHealth,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    var agentId = context.Request.Query["agent_id"].FirstOrDefault();
    return Results.Ok(await sourceHealth.SearchAsync(agentId, cancellationToken));
});

app.MapGet("/api/v1/inventory", async Task<IResult> (
    HttpContext context,
    AssetInventoryRepository inventory,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    var agentId = context.Request.Query["agent_id"].FirstOrDefault();
    var snapshotType = context.Request.Query["snapshot_type"].FirstOrDefault();
    return Results.Ok(new { snapshots = await inventory.SearchAsync(agentId, snapshotType, cancellationToken) });
});

app.MapGet("/api/v1/alerts", async Task<IResult> (
    HttpContext context,
    AlertRepository alerts,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    var status = context.Request.Query["status"].FirstOrDefault();
    return Results.Ok(new { alerts = await alerts.SearchAlertsAsync(status, cancellationToken) });
});

app.MapGet("/api/v1/alerts/{alertId:guid}", async Task<IResult> (
    Guid alertId,
    HttpContext context,
    AlertRepository alerts,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    var alert = await alerts.GetAlertAsync(alertId, cancellationToken);
    return alert is null ? Results.NotFound() : Results.Ok(alert);
});

app.MapGet("/api/v1/graphs", async Task<IResult> (
    HttpContext context,
    InvestigationGraphRepository graphs,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    try
    {
        return Results.Ok(await graphs.CreateAsync(request, "review-token-operator", cancellationToken));
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    try
    {
        var updated = await graphs.UpdateAsync(graphId, request, "review-token-operator", cancellationToken);
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    var archived = await graphs.ArchiveAsync(graphId, "review-token-operator", cancellationToken);
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    try
    {
        return Results.Ok(await graphs.AddNodeAsync(graphId, request, "review-token-operator", cancellationToken));
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    try
    {
        return Results.Ok(await graphs.AddEdgeAsync(graphId, request, "review-token-operator", cancellationToken));
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    try
    {
        return Results.Ok(await graphs.CreateSocAgentProposalAsync(graphId, request.Instruction, "review-token-operator", cancellationToken));
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    var proposal = await graphs.ApplyProposalAsync(graphId, proposalId, "review-token-operator", cancellationToken);
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    if (string.IsNullOrWhiteSpace(request.Question) || request.Question.Length > 4000)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["question"] = new[] { "Question is required and must be 4000 characters or less." }
        });
    }

    return Results.Ok(await socAgent.AskAsync(request, cancellationToken));
});

app.MapGet("/api/v1/soc-agent/status", (HttpContext context, SocAgentService socAgent, TokenService tokens, IConfiguration configuration) =>
{
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    var detail = await socAgent.GetSessionDetailAsync(sessionId, cancellationToken);
    return detail is null ? Results.NotFound() : Results.Ok(detail);
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
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
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
        return Results.Ok(await socAgent.SendChatMessageAsync(sessionId, request, cancellationToken));
    }
    catch (KeyNotFoundException)
    {
        return Results.NotFound();
    }
});

app.MapGet("/api/v1/detections/rules", async Task<IResult> (
    HttpContext context,
    AlertRepository alerts,
    TokenService tokens,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    if (!tokens.ValidateReviewToken(context, configuration))
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new { rules = await alerts.GetRulesAsync(cancellationToken) });
});

app.MapRazorPages();

app.Run();

static int ParseIntOrDefault(string? value, int fallback)
{
    return int.TryParse(value, out var parsed) ? parsed : fallback;
}

public partial class Program;
