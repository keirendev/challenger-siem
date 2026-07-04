using Challenger.Siem.Api.Database;

namespace Challenger.Siem.Api.Auth;

public sealed class AgentAuthenticator(TokenService tokenService, AgentRepository agents)
{
    public async Task<bool> AuthenticateAsync(HttpContext context, string agentId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(agentId))
        {
            return false;
        }

        var token = tokenService.GetBearerToken(context);
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        var tokenHash = tokenService.HashToken(token);
        return await agents.IsAgentTokenValidAsync(agentId, tokenHash, cancellationToken);
    }
}
