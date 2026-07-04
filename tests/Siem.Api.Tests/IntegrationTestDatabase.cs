using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class IntegrationTestDatabase : IAsyncLifetime
{
    public string? ConnectionString { get; private set; }

    public async Task InitializeAsync()
    {
        ConnectionString = Environment.GetEnvironmentVariable("CHALLENGER_SIEM_TEST_DATABASE")
            ?? Environment.GetEnvironmentVariable("ConnectionStrings__SiemTestDatabase");

        if (string.IsNullOrWhiteSpace(ConnectionString))
        {
            return;
        }

        var schemaPath = FindRepositoryFile("server/Siem.Api/Database/001_initial.sql");
        var schemaSql = await File.ReadAllTextAsync(schemaPath);
        await using var dataSource = NpgsqlDataSource.Create(ConnectionString);
        await using var command = dataSource.CreateCommand(schemaSql);
        await command.ExecuteNonQueryAsync();
    }

    public Task DisposeAsync()
    {
        return Task.CompletedTask;
    }

    public string RequireConnectionString()
    {
        if (string.IsNullOrWhiteSpace(ConnectionString))
        {
            throw new InvalidOperationException(
                "PostgreSQL integration connection string was not configured at test execution time.");
        }

        return ConnectionString;
    }

    private static string FindRepositoryFile(string relativePath)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName, relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        throw new FileNotFoundException($"Could not locate repository file: {relativePath}");
    }
}

[CollectionDefinition(Name)]
public sealed class PostgresIntegrationCollection : ICollectionFixture<IntegrationTestDatabase>
{
    public const string Name = "PostgreSQL integration";
}
