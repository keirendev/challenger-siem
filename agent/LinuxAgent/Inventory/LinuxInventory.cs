using Challenger.Siem.Contracts.V1;
namespace Challenger.Siem.LinuxAgent.Inventory;
public static class LinuxInventory
{
 public static AssetInventorySnapshot Collect(string id,string hostname)=>new(){AgentId=id,Hostname=hostname,SnapshotType="linux_host",Items=new[]{new InventoryItem{Kind="operating_system",Name=System.Runtime.InteropServices.RuntimeInformation.OSDescription,Metadata=new Dictionary<string,string>{{"architecture",System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString()}}}},Summary=new Dictionary<string,string>{{"platform","linux"}}};
}
