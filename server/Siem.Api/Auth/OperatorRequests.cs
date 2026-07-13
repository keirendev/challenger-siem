namespace Challenger.Siem.Api.Auth;

public sealed record OperatorCreateRequest(string Username, string DisplayName, string Role, string Password);
public sealed record OperatorPasswordChangeRequest(string CurrentPassword, string NewPassword);
