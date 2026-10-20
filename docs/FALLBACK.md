# Model fallback

The selected primary is tried first on every new request. Fresh configurations
prefer the installed Codex CLI; saved provider choices are preserved.

Use **Settings → Fallback policy** or `vulnora fallback` to inspect and change:

| Setting | Default | Behavior |
| --- | --- | --- |
| Fallback Enabled | On | Allows the configured replacement model. No model is downloaded. |
| Fallback Model | Selected local model | Any supported configured provider/model can be chosen. |
| Fallback on API Error | On | Switches after bounded technical retries, including connection errors and empty responses. |
| Fallback on Rate Limit | On | Switches on rate limits or exhausted quota. Exhausted quota is not retried on the same model. |
| Fallback on Refusal | Off | Allows reevaluation of technical or unclear refusals with the original request context. |

Safety refusals, including structured provider refusal fields and content filters,
never advance to another model. Text classification is heuristic; an ambiguous
refusal stays with the primary unless explicitly enabled. Fallback does not add
authorization claims or alter the supplied scope.

```sh
vulnora fallback
vulnora fallback --enabled true --provider local --model my-installed-model
vulnora fallback --on-api-error true --on-rate-limit true --on-refusal false
vulnora fallback --enabled false
```

These commands update the same `config.json` used by the TUI:

```json
{
  "fallback": {
    "enabled": true,
    "provider": "local",
    "model": "",
    "onApiError": true,
    "onRateLimit": true,
    "onRefusal": false
  }
}
```

An empty model selects that provider's configured default. For local discovery,
use **Settings → Local models / fallback**, including manual endpoint/model entry
and **Retry discovery**. Selecting a fallback does not change the primary.

Legacy `VULNORA_MODEL_FALLBACK=local` selects the configured local model;
`off` disables the ladder, and `true` selects the legacy configured-provider
ladder. An explicit saved fallback choice takes precedence. All ladders are
deduplicated and traversed once, with at most three attempts per model.

Transitions, recovery results and stopped decisions are recorded in
`~/.vulnora/logs/model-fallback.jsonl` with request IDs and redacted diagnostics.
`VULNORA_FALLBACK_AUDIT_LOG` can select another file. Project journals also retain
provider transitions. An Ollama model is retained when actually used and released
on graceful exit, including models selected during the session.

Provider response formats:
[OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create),
[Claude stop reasons](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons).
