using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Contracts.V1;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class OperatorSecurityTests
{
    [Fact]
    public void PasswordHashesAreSaltedAndVerifyWithoutStoringPassword()
    {
        var hasher=new OperatorPasswordHasher();const string password="Synthetic-Strong1!";var first=hasher.Hash(password);var second=hasher.Hash(password);
        Assert.NotEqual(first,second);Assert.True(hasher.Verify(password,first));Assert.False(hasher.Verify("Synthetic-Wrong1!",first));Assert.DoesNotContain(password,first,StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(OperatorRoles.Viewer,OperatorPermission.ReviewMetadata,true)]
    [InlineData(OperatorRoles.Viewer,OperatorPermission.ReviewSensitive,false)]
    [InlineData(OperatorRoles.Analyst,OperatorPermission.ManageInvestigations,true)]
    [InlineData(OperatorRoles.Analyst,OperatorPermission.ManageDetections,false)]
    [InlineData(OperatorRoles.DetectionEngineer,OperatorPermission.ManageDetections,true)]
    [InlineData(OperatorRoles.DetectionEngineer,OperatorPermission.ManageOperators,false)]
    [InlineData(OperatorRoles.Admin,OperatorPermission.ManageOperators,true)]
    [InlineData(OperatorRoles.Admin,OperatorPermission.ReviewAudit,true)]
    public void ExactRolePermissionMatrixIsEnforced(string role,OperatorPermission permission,bool expected)=>Assert.Equal(expected,OperatorAuthorization.HasPermission(role,permission));

    [Fact]
    public void NonAdminEventSerializationRedactsRawCommandsAccountsPathsAndNetworkData()
    {
        using var doc=JsonDocument.Parse("{\"secret\":\"synthetic-only\"}");
        var source=new EventEnvelope{Message="Synthetic sensitive text",Raw=doc.RootElement.Clone(),Normalized=new NormalizedEventFields{UserName="synthetic-user",TargetUserName="synthetic-target",ProcessCommandLine="tool --synthetic",SourceIp="192.0.2.10",DestinationIp="198.51.100.20",FilePath="C:\\Synthetic\\item.txt",RegistryKey="HKLM\\Synthetic",Process=new ProcessTelemetryConcept{Executable="C:\\Synthetic\\tool.exe",CommandLine="tool --synthetic"},User=new UserTelemetryConcept{Name="synthetic-user"},Network=new NetworkTelemetryConcept{SourceIp="192.0.2.10"},File=new FileTelemetryConcept{Path="C:\\Synthetic\\item.txt"}}};
        foreach(var role in new[]{OperatorRoles.Viewer,OperatorRoles.Analyst,OperatorRoles.DetectionEngineer})
        {var result=EventFieldPolicy.Apply(source,role);Assert.Equal(JsonValueKind.Object,result.Raw.ValueKind);Assert.Empty(result.Raw.EnumerateObject());Assert.DoesNotContain("Synthetic sensitive",result.Message,StringComparison.Ordinal);Assert.Null(result.Normalized!.UserName);Assert.Null(result.Normalized.ProcessCommandLine);Assert.Null(result.Normalized.SourceIp);Assert.Null(result.Normalized.FilePath);Assert.Null(result.Normalized.User);Assert.Null(result.Normalized.Network);Assert.Null(result.Normalized.File);Assert.Null(result.Normalized.Process!.Executable);}
        Assert.Same(source,EventFieldPolicy.Apply(source,OperatorRoles.Admin));
    }

    [Fact]
    public void NonAdminAlertPolicyRemovesEntityAndEvidenceContext()
    {
        var alert=new AlertRecord{Summary="Synthetic account at 192.0.2.10",AffectedEntities=new[]{new EventEntity{Type="user",Value="synthetic-user"}},Evidence=new[]{new AlertEvidenceRecord{Summary="Synthetic command and path"}}};
        var redacted=AlertFieldPolicy.Apply(alert,OperatorRoles.Viewer);Assert.Empty(redacted.AffectedEntities);Assert.DoesNotContain("192.0.2.10",redacted.Summary,StringComparison.Ordinal);Assert.All(redacted.Evidence,item=>Assert.StartsWith("[redacted",item.Summary,StringComparison.Ordinal));Assert.Same(alert,AlertFieldPolicy.Apply(alert,OperatorRoles.Admin));
    }

    [Theory]
    [InlineData("short")]
    [InlineData("alllowercasebutlong1!")]
    [InlineData("ALLUPPERCASEBUTLONG1!")]
    public void WeakPasswordsAreRejected(string password)=>Assert.Throws<ArgumentException>(()=>new OperatorPasswordHasher().Hash(password));
}
