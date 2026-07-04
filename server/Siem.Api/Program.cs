using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Api.Review;
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
builder.Services.AddScoped<IngestionErrorRepository>();
builder.Services.AddScoped<ReviewRepository>();
builder.Services.Configure<ReviewOptions>(builder.Configuration.GetSection(ReviewOptions.SectionName));
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

app.MapRazorPages();

app.Run();

static int ParseIntOrDefault(string? value, int fallback)
{
    return int.TryParse(value, out var parsed) ? parsed : fallback;
}

public partial class Program;
