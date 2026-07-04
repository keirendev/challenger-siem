using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Queue;

public sealed record QueuedEvent(long QueueId, EventEnvelope Envelope);
