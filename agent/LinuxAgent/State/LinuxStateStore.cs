using System.Text.Json;
namespace Challenger.Siem.LinuxAgent.State;
public sealed class LinuxStateStore(string path)
{
 public async Task WriteEnrollmentAsync(string agentId,CancellationToken ct){Directory.CreateDirectory(Path.GetDirectoryName(path)!);var temp=path+".tmp";await File.WriteAllTextAsync(temp,JsonSerializer.Serialize(new {agent_id=agentId,enrolled_at=DateTimeOffset.UtcNow}),ct);File.Move(temp,path,true);}
}
