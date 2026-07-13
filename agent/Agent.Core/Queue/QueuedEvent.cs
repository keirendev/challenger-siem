using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Agent.Core.Queue;

public sealed record QueuedEvent(long QueueId, EventEnvelope Envelope, int SendAttempts, DateTimeOffset? LastAttemptAt);
