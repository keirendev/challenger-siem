using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Collectors;

public sealed record CollectedWindowsEvent(long RecordId, EventEnvelope Envelope);
