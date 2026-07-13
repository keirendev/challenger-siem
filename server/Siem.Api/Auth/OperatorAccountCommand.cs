using Challenger.Siem.Api.Database;

namespace Challenger.Siem.Api.Auth;

public static class OperatorAccountCommand
{
    public static async Task<int?> TryRunAsync(string[] args, IServiceProvider services, CancellationToken cancellationToken)
    {
        if (args.Length < 2 || args[0] != "operator") return null;
        var action=args[1]; var username=Value(args,"--username") ?? throw new ArgumentException("--username is required.");
        var password=Environment.GetEnvironmentVariable("SIEM_OPERATOR_PASSWORD");
        await using var scope=services.CreateAsyncScope(); var repository=scope.ServiceProvider.GetRequiredService<OperatorRepository>(); var audit=scope.ServiceProvider.GetRequiredService<SecurityAuditRepository>();
        if(action=="bootstrap")
        {
            if(string.IsNullOrEmpty(password))throw new InvalidOperationException("SIEM_OPERATOR_PASSWORD is required.");
            var role=Value(args,"--role")??OperatorRoles.Admin;var display=Value(args,"--display-name")??username;
            var op=await repository.CreateAsync(username,display,role,password,true,cancellationToken);
            await audit.RecordAsync(op.OperatorId,op.Username,"operator.bootstrap","success","operator",op.OperatorId.ToString(),null,new Dictionary<string,object?>{{"role",role}},cancellationToken);
            Console.WriteLine($"Operator {op.Username} bootstrapped with role {op.Role}."); return 0;
        }
        var existing=await repository.FindByUsernameAsync(username,cancellationToken)??throw new InvalidOperationException("Operator was not found.");
        if(action is "recover" or "change-password")
        {
            if(string.IsNullOrEmpty(password))throw new InvalidOperationException("SIEM_OPERATOR_PASSWORD is required.");
            await repository.ChangePasswordAsync(existing.OperatorId,password,action=="recover",cancellationToken);
            await audit.RecordAsync(existing.OperatorId,existing.Username,$"operator.{action}","success","operator",existing.OperatorId.ToString(),null,null,cancellationToken);
            Console.WriteLine($"Operator {existing.Username} credentials changed and sessions revoked."); return 0;
        }
        if(action=="rotate-api-token")
        {
            var token=await repository.RotateApiTokenAsync(existing.OperatorId,cancellationToken);
            await audit.RecordAsync(existing.OperatorId,existing.Username,"operator.api_token.rotate","success","operator",existing.OperatorId.ToString(),null,null,cancellationToken);
            Console.WriteLine("Store this operator API credential now; it will not be shown again:"); Console.WriteLine(token); return 0;
        }
        throw new ArgumentException("Action must be bootstrap, change-password, recover, or rotate-api-token.");
    }
    private static string? Value(string[] args,string key){var i=Array.IndexOf(args,key);return i>=0&&i+1<args.Length?args[i+1]:null;}
}
