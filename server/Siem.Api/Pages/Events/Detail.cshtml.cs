using System.Text.Json;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Events;

public sealed class DetailModel(EventRepository eventRepository, ILogger<DetailModel> logger) : PageModel
{
    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };

    [BindProperty(SupportsGet = true, Name = "agent_id")]
    public string AgentId { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true, Name = "event_id")]
    public Guid EventId { get; set; }

    public EventEnvelope? Envelope { get; private set; }

    public string RawJson { get; private set; } = "{}";

    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(AgentId) || EventId == Guid.Empty)
        {
            ErrorMessage = "A valid agent_id and event_id are required.";
            return Page();
        }

        try
        {
            Envelope = await eventRepository.GetEventAsync(AgentId, EventId, cancellationToken);
            if (Envelope is null)
            {
                return NotFound();
            }

            RawJson = JsonSerializer.Serialize(Envelope.Raw, PrettyJson);
            return Page();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Event detail could not be loaded for agent {AgentId} and event {EventId}.", AgentId, EventId);
            ErrorMessage = "Event detail is currently unavailable.";
            return Page();
        }
    }
}
