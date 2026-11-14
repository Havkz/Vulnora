# Direct CLI

`vulnora` opens the existing terminal UI. `vulnora run` uses the same
`ProjectSession`, scanner, project directory, checkpoints and evidence journal.
Only assess targets you own or are explicitly authorized to test.

```sh
vulnora run https://authorized.example --name "Website assessment" --intensity stealth
vulnora run --resume <project-uuid>
vulnora run https://authorized.example --provider codex --model codex-default --reasoning high
vulnora run https://authorized.example --provider claude --model sonnet --reasoning medium
vulnora run https://authorized.example --fallback-provider local --fallback-model installed-model:7b
vulnora run https://authorized.example --scope api.authorized.example --exclude admin.authorized.example --exclude-tool nmap_scan --rate-limit 2
vulnora run --help
```

Use an explicit HTTP(S) URL. Resume accepts a saved UUID and preserves its target
and assessment rules; it cannot be combined with a new URL, name, intensity or scope/rate override. Projects
created in either interface are accessible from both. Provider/model overrides
apply to this process and do not modify saved settings or the installed CLI's
own configuration. `claude` selects the installed Claude Code CLI.

| Option | Behavior |
| --- | --- |
| `--name` | Name of a new project; defaults to the target hostname. |
| `--intensity auto\|stealth\|aggressive` | Existing scanning behavior and adaptive traffic policy. |
| `--provider`, `--model`, `--reasoning` | Inference selection; reasoning applies to Codex/Claude. |
| `--fallback-enabled true\|false` | Enable or disable fallback for this run. |
| `--fallback-provider`, `--fallback-model` | Override the alternative provider/model. |
| `--fallback-on-api-error`, `--fallback-on-rate-limit`, `--fallback-on-refusal` | Boolean overrides of the [central policy](FALLBACK.md); safety refusals never reroute. |
| `--verbose` | Expand process output using the existing transcript formatter. |
| `--scope <host>` | Additional authorized hostname/IP; repeat for multiple hosts. Domains include their subdomains. |
| `--exclude <host>` | Exclude a requested hostname/IP and its subdomains, even if an allow rule matches. Repeatable. |
| `--exclude-tool <id>` | Remove an exact tool ID from model definitions and block its execution. Repeatable. |
| `--exclude-risk <class>` | Exclude a risk class: `local_read`, `passive`, `active`, `intrusive`, `credential`, or `dangerous`. Repeatable; overrides tool approval. |
| `--rate-limit <integer>` | Per-host ceiling, 1–1000 requests/second; existing intensity/backoff may be slower. |
| `--resume` | Reopen a saved project without creating another one. |
| `--config <file>` | Load a version 1 JSON run profile; explicit CLI flags take precedence. |
| `--output <directory>` | Export reports here; checkpoints and logs stay in the shared project store. |
| `--report-format markdown\|json\|both` | Export format, defaulting to Markdown. |

Use bare hostnames or IPs in host rules. Paths, ports, wildcard expressions and
CIDRs are rejected rather than silently widened. Excluding the primary target
is an error. These options persist in both the project record and checkpoint;
changing the saved rules without their matching checkpoint prevents resume.
In the TUI, press `R` on the existing READY screen to edit rules before starting.
See [scope enforcement and limits](SCOPE_AND_AUTHORIZATION.md#saved-assessment-rules).

The CLI prints the project UUID and resume command before starting. Graceful
interrupts cancel work, drain outstanding tasks and persist the checkpoint
before releasing the project lease and used local models. Forced termination
cannot guarantee cleanup; the next session uses existing checkpoint recovery.
Interrupted calls requiring review remain paused; inspect and approve recovery
through the TUI. A resumed completed project exports its saved report without
starting a new scan.

Reports default to the shared projects directory. Exit
code `0` means the engine reported completed coverage (possibly with warnings),
`2` means paused or incomplete, and `1` means a command or persistence failure.
Handled SIGINT/SIGTERM use `130`/`143`. Completion does not prove the absence of
vulnerabilities.

## Provider checks and discovery

```sh
vulnora models --provider local
vulnora test --provider local --model installed-model:7b
vulnora test --provider codex
vulnora fallback
```

Local discovery queries the configured Ollama/OpenAI-compatible endpoint and
does not load weights or run inference. Other providers currently show the
built-in model catalogue. `test` performs one inference validation on the selected
provider only, with no fallback. A local model used by that test is released on
exit; Codex is not tested when `--provider local` is selected.

Configuration uses the same saved settings and `VULNORA_CONFIG_DIR` as the TUI.

## Run configuration files

`vulnora run --config assessment.json` reads defaults without modifying the file
or saved settings. A profile uses the same options as `run`, in camelCase:

```json
{
  "version": 1,
  "target": "https://authorized.example",
  "name": "Website assessment",
  "intensity": "stealth",
  "provider": "codex",
  "reasoning": "high",
  "fallbackEnabled": true,
  "fallbackProvider": "local",
  "fallbackModel": "your-installed-model:7b",
  "fallbackOnApiError": true,
  "fallbackOnRateLimit": true,
  "fallbackOnRefusal": false,
  "scope": ["api.authorized.example"],
  "exclude": ["admin.authorized.example"],
  "excludeTool": ["nmap_scan"],
  "excludeRisk": ["dangerous", "credential"],
  "rateLimit": 2,
  "output": "./reports",
  "reportFormat": "both"
}
```

Optional `model` and `verbose` are also supported. Replace the example model ID
with one listed by `vulnora models --provider local`. API keys, endpoint URLs and
CLI executable settings remain in central settings/environment configuration;
profiles cannot inject environment variables or shell commands.

Precedence is explicit flags, then the run profile, then central settings/defaults.
A supplied host/tool/risk list replaces that entire profile list. Changing a provider
with a flag clears the profile's model and reasoning for the previous provider;
changing the fallback provider clears its profile model. Relative `output` paths
in files resolve beside the file; paths supplied by flags resolve from the working
directory. JSON must be UTF-8, at most 64 KiB; unknown keys and malformed values
fail before starting work. Resume profiles must omit target/name/intensity and
assessment rules because the saved project owns those values.

## Report exports

```sh
vulnora run https://authorized.example --output ./reports --report-format both
vulnora report <project-uuid> --format json --output ./reports
```

The `report` command exports a saved snapshot without contacting a model or
starting a scan. In the TUI, open results and press `E` to choose Markdown, JSON
or both and an export directory. Files use `<project-uuid>.report.md` and
`<project-uuid>.report.json`; exporting again atomically replaces that report.

New reports include findings and evidence, verification status, recommendations,
recorded coverage with evidence IDs, phase outcomes, scope rules and limitations.
JSON has `schemaVersion: 1`. Coverage remains the engine's runtime classification,
not an independent proof of completeness. Findings sharing a target are labelled
as correlations, not verified attack chains. A zero-finding report does not assert
that the website is secure. Known secrets are redacted; review sensitive evidence
before sharing it.

Older saved Markdown reports remain readable/exportable without being rewritten;
JSON is available only when a structured snapshot was saved. The original project,
checkpoint, credentials and raw model history are not bundled into exports.
