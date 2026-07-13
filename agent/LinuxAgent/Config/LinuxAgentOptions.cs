using Challenger.Siem.Agent.Core.Transport;
namespace Challenger.Siem.LinuxAgent.Config;
public sealed class LinuxAgentOptions : IAgentTransportConfiguration
{
 public const string SectionName="Agent"; public string AgentId {get;set;}=""; public Uri? ServerBaseUrl {get;set;} public string ApiToken {get;set;}=""; public string EnrollmentToken {get;set;}="";
 public int HeartbeatIntervalSeconds {get;set;}=60; public int InventoryIntervalSeconds {get;set;}=3600; public int DrainBatchSize {get;set;}=100;
 public QueueOptions Queue {get;set;}=new(); public StateOptions State {get;set;}=new();
}
public sealed class QueueOptions { public string Path {get;set;}="/var/lib/challenger-siem-agent/queue.sqlite"; public int MaxSizeMb {get;set;}=512; public int MaxSendAttempts {get;set;}=10; public int MaxBackoffSeconds {get;set;}=300; public int WarningSizePercent {get;set;}=80; }
public sealed class StateOptions { public string Path {get;set;}="/var/lib/challenger-siem-agent/state.json"; }
