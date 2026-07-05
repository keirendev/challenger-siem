using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.SocAgent;

public sealed class SocAgentLiveRunCoordinator(
    SocAgentService socAgent,
    SocAgentLiveRunRegistry registry,
    IServiceScopeFactory scopeFactory,
    ILogger<SocAgentLiveRunCoordinator> logger)
{
    public async Task<SocAgentLiveRunStartResponse> StartRunAsync(
        SocAgentLiveRunStartRequest request,
        CancellationToken cancellationToken)
    {
        if (request.SessionId.HasValue && registry.TryGetActiveRunForSession(request.SessionId.Value, out _))
        {
            throw new InvalidOperationException("A soc-agent run is already active for this session.");
        }

        var turn = await socAgent.StartChatTurnAsync(
            request.SessionId,
            new SocAgentChatRequest
            {
                Message = request.Message,
                ContextAgentId = request.ContextAgentId,
                ContextEventId = request.ContextEventId
            },
            cancellationToken);

        var state = registry.CreateRun(turn);
        state.Append("session_created", new Dictionary<string, object?>
        {
            ["session"] = turn.Session
        });
        state.Append("message_created", new Dictionary<string, object?>
        {
            ["message"] = turn.UserMessage
        });
        state.Append("run_started", new Dictionary<string, object?>
        {
            ["status"] = "running",
            ["message"] = "soc-agent started a live SIEM review turn."
        });
        state.Append("provider_status", new Dictionary<string, object?>
        {
            ["provider_status"] = turn.ProviderStatus
        });

        _ = Task.Run(() => CompleteRunAsync(state), CancellationToken.None);

        return new SocAgentLiveRunStartResponse
        {
            RunId = state.RunId,
            Session = turn.Session,
            UserMessage = turn.UserMessage,
            ProviderStatus = turn.ProviderStatus,
            NextSequence = state.LastSequence
        };
    }

    public SocAgentLiveRunCancelResponse? CancelRun(Guid runId)
    {
        if (!registry.TryGetRun(runId, out var state))
        {
            return null;
        }

        var cancelled = state.RequestCancel();
        return new SocAgentLiveRunCancelResponse
        {
            RunId = state.RunId,
            SessionId = state.SessionId,
            Cancelled = cancelled,
            Status = state.Status
        };
    }

    public SocAgentLiveActiveRunResponse GetActiveRun(Guid sessionId)
    {
        if (!registry.TryGetActiveRunForSession(sessionId, out var state))
        {
            return new SocAgentLiveActiveRunResponse
            {
                HasActiveRun = false,
                SessionId = sessionId,
                Status = "idle"
            };
        }

        return new SocAgentLiveActiveRunResponse
        {
            HasActiveRun = true,
            RunId = state.RunId,
            SessionId = state.SessionId,
            LastSequence = state.LastSequence,
            Status = state.Status
        };
    }

    private async Task CompleteRunAsync(SocAgentLiveRunState state)
    {
        var completionStatus = "complete";
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var scopedSocAgent = scope.ServiceProvider.GetRequiredService<SocAgentService>();
            var progress = new SocAgentLiveProgressSink(state);
            var response = await scopedSocAgent.CompleteChatTurnAsync(
                state.Turn,
                progress,
                state.CancelSource.Token);

            foreach (var chunk in SplitContent(response.AssistantMessage.Content, 700))
            {
                state.Append("content_delta", new Dictionary<string, object?>
                {
                    ["message_id"] = response.AssistantMessage.MessageId,
                    ["delta"] = chunk
                });
            }

            state.Append("message_created", new Dictionary<string, object?>
            {
                ["message"] = response.AssistantMessage
            });

            var errorCode = response.AssistantMessage.ErrorCode;
            if (string.Equals(errorCode, "cancelled", StringComparison.OrdinalIgnoreCase))
            {
                completionStatus = "cancelled";
                state.Append("run_complete", new Dictionary<string, object?>
                {
                    ["status"] = "cancelled",
                    ["cancelled"] = true,
                    ["session"] = response.Session,
                    ["assistant_message"] = response.AssistantMessage
                });
            }
            else if (!string.IsNullOrWhiteSpace(errorCode))
            {
                completionStatus = "error";
                state.Append("run_error", new Dictionary<string, object?>
                {
                    ["error_code"] = errorCode,
                    ["message"] = "soc-agent completed with an operator-safe error state."
                });
                state.Append("run_complete", new Dictionary<string, object?>
                {
                    ["status"] = "error",
                    ["cancelled"] = false,
                    ["session"] = response.Session,
                    ["assistant_message"] = response.AssistantMessage
                });
            }
            else
            {
                state.Append("run_complete", new Dictionary<string, object?>
                {
                    ["status"] = "complete",
                    ["cancelled"] = false,
                    ["session"] = response.Session,
                    ["assistant_message"] = response.AssistantMessage
                });
            }
        }
        catch (Exception ex)
        {
            completionStatus = "error";
            logger.LogWarning(ex, "soc-agent live run failed before it could persist a bounded assistant response.");
            state.Append("run_error", new Dictionary<string, object?>
            {
                ["error_code"] = ex.GetType().Name,
                ["message"] = "soc-agent live run failed before completion. Confirm the database schema is applied and try again."
            });
            state.Append("run_complete", new Dictionary<string, object?>
            {
                ["status"] = "error",
                ["cancelled"] = false
            });
        }
        finally
        {
            registry.CompleteRun(state, completionStatus);
        }
    }

    private static IEnumerable<string> SplitContent(string content, int chunkSize)
    {
        if (string.IsNullOrEmpty(content))
        {
            yield break;
        }

        for (var index = 0; index < content.Length; index += chunkSize)
        {
            var length = Math.Min(chunkSize, content.Length - index);
            yield return content.Substring(index, length);
        }
    }

    private sealed class SocAgentLiveProgressSink(SocAgentLiveRunState state) : ISocAgentProgressSink
    {
        public ValueTask ProviderStatusAsync(SocAgentProviderStatusResponse status, CancellationToken cancellationToken)
        {
            state.Append("provider_status", new Dictionary<string, object?>
            {
                ["provider_status"] = status
            });
            return ValueTask.CompletedTask;
        }

        public ValueTask ToolStartedAsync(string toolName, string summary, CancellationToken cancellationToken)
        {
            state.Append("tool_started", new Dictionary<string, object?>
            {
                ["tool_name"] = toolName,
                ["summary"] = summary,
                ["status"] = "running"
            });
            return ValueTask.CompletedTask;
        }

        public ValueTask ToolFinishedAsync(SocAgentToolRunSummary toolRun, CancellationToken cancellationToken)
        {
            state.Append("tool_finished", new Dictionary<string, object?>
            {
                ["tool_name"] = toolRun.ToolName,
                ["summary"] = toolRun.Summary,
                ["row_count"] = toolRun.RowCount,
                ["status"] = "ok",
                ["tool_run"] = toolRun
            });
            return ValueTask.CompletedTask;
        }

        public ValueTask CitationAddedAsync(SocAgentCitation citation, CancellationToken cancellationToken)
        {
            state.Append("citation_added", new Dictionary<string, object?>
            {
                ["citation"] = citation
            });
            return ValueTask.CompletedTask;
        }
    }
}
