using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Challenger.Siem.Agent.Core.Security;

public static class AgentConfigurationHasher
{
    private static readonly string[] SecretKeyFragments =
    {
        "token",
        "password",
        "secret",
        "key"
    };

    public static string ComputeFileHash(string path)
    {
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        using var stream = File.OpenRead(path);
        var digest = SHA256.HashData(stream);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static string ComputeConfigurationHash(string path)
    {
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        var json = File.ReadAllText(path, Encoding.UTF8);
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(json);
        }
        catch (System.Text.Json.JsonException)
        {
            node = JsonValue.Create(json);
        }

        RedactSecrets(node, parentKey: string.Empty);
        var canonical = node?.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = false }) ?? string.Empty;
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static void RedactSecrets(JsonNode? node, string parentKey)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var property in obj.ToArray())
                {
                    if (IsSecretKey(property.Key))
                    {
                        obj[property.Key] = "<redacted>";
                    }
                    else
                    {
                        RedactSecrets(property.Value, property.Key);
                    }
                }

                break;
            case JsonArray array:
                foreach (var item in array)
                {
                    RedactSecrets(item, parentKey);
                }

                break;
        }
    }

    private static bool IsSecretKey(string key) => SecretKeyFragments.Any(fragment => key.Contains(fragment, StringComparison.OrdinalIgnoreCase));
}
