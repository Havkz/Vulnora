# Vulnora

Persistent AI-assisted website and API security testing in the terminal.

Vulnora combines the existing scanner, shared evidence and reports with a
VoidAccess-inspired CLI, saved projects, bounded adaptive scan modes, authenticated
Codex/Claude CLI providers and an installed Ollama fallback.

## Run from this private repository

Requires Node.js **22.12.0 or newer**, npm, Git and an ANSI-compatible terminal.
External scanner commands are provided by the Linux/Kali arsenal environment.

```bash
gh repo clone Havkz/Vulnora
cd Vulnora
npm ci
npm run build
npm start
```

The package executable is `vulnora`. On Windows, install a committed WSL release
and the shell command from the checkout:

```powershell
pwsh -NoProfile -File scripts/setup-windows-arsenal.ps1
pwsh -NoProfile -File scripts/install-windows-alias.ps1
vulnora
```

Setup reuses the existing Kali arsenal and provider authentication. New commits
can be installed by rerunning setup; normal launches keep the installed release.
The command has been checked in fresh PowerShell 7, Windows PowerShell and CMD
sessions. See the [Windows installation guide](docs/WINDOWS_ARSENAL.md) and
[milestone ledger](docs/VULNORA_MILESTONE.md) for runtime evidence and remaining
visual/acceptance gates.

## Projects and navigation

The main menu contains **Create New Project**, **Resume Project**, and **Settings**.
Use arrows and Enter to select; Esc returns and Ctrl+C saves and quits.

Create a project, enter a URL, hostname, IPv4 or IPv6 address, then confirm
**READY — Press Enter to start**. The original target remains visible. Entering a
target alone does not begin scanning. The workflow tests websites and APIs; the
browser dashboard and mobile/binary target picker are removed.

Use PgUp/PgDn or Home/End to inspect a long target in READY or project metadata
in the resume picker. Small windows retain the confirmation/completion prompts;
saved target strings, reports and detailed logs remain complete.

Resume Project shows saved status, progress, target and timestamps. Name/target
drafts also survive interruption. During a scan, PgUp/PgDn scroll the complete log
history and End returns to live output. Esc stops scheduling and drains or cancels
active work before opening the pause menu. Settings are available from both menus.

Completion waits for **Press Enter to view results**. Findings, classifications,
evidence, explanations and recommendations use the existing report path. Reports
are saved with the project and exported to `<project-id>.report.md`. Completed
projects reopen saved results without starting another scan.

## Persistent recovery

Projects and journals live under `~/.vulnora/projects/`. Set
`VULNORA_CONFIG_DIR` to choose another application configuration directory.

Atomic checkpoints retain missions, ordered tasks and decomposed child queues,
parameters, AI context, pending tool calls, completed evidence, budgets, adaptive
backoff and remaining cooldown. Resume skips completed work and uses completed
tool receipts when available. Unknown state-changing requests remain held for
inspection; interrupted read-only requests restart only when replay is safe.
TCP exchanges and opaque external scanner processes do not resume mid-packet.

Ctrl+C flushes checkpoints and logs, releases the project lease, stops owned work
and restores terminal state. Abrupt process termination cannot guarantee cleanup
or model unloading; completed checkpoints remain available for recovery.

Legacy Tempest application data migrates into the Vulnora namespace without
deleting the source or overwriting existing destination files. Migration records
include hashes. Provider authentication files are neither copied nor modified.
The original repository is retained separately; development uses the private
[Havkz/Vulnora](https://github.com/Havkz/Vulnora) repository.

## Scan modes

Settings offers **Auto**, **Stealth**, and **Aggressive**. Changing a paused
project's mode applies and saves it without resetting scope, budgets or server backoff.

| Mode | Active operators | HTTP requests per host | Minimum interval | Extra safe HTTP attempts |
| --- | ---: | ---: | ---: | ---: |
| Auto | 3 | 2 | 250 ms | 1 |
| Stealth | 1 | 1 | 1000 ms | 0 |
| Aggressive | 6 | 4 | 50 ms | 2 |

429/5xx, transport failures and slow responses reduce load; stable observations
gradually restore the preset. Hard scope and resource limits remain enforced.
Stealth uses conservative request behavior without monitoring evasion. Only
bodyless GET/HEAD requests retry automatically. Each additional built-in HTTP
request is durably charged before sending.

The controller works without AI. A model can prioritize checks using findings
and the enforced limits. External processes use their supported native controls
and an exclusive host lane; some internal counts remain estimates.
See [exact limits and boundaries](docs/SCAN_MODES.md).

## Providers and Ollama fallback

Configure the provider/model through **Settings → Change Default Model / Provider**.
Vulnora detects installed Codex/Claude CLI applications, checks their official
version/authentication commands and validates real inference. Non-interactive
calls reuse supported existing login; private credentials remain owned by those applications.

Startup discovers installed Ollama models, validates the selected model and keeps
it loaded throughout the session. No model is downloaded automatically. Select
the desired model in Settings when multiple models are installed.

The interactive fallback chain is:

1. Selected primary provider/model.
2. Configured, validated installed Ollama model.
3. Deterministic evidence-only checks where supported.

Switches and actual provider/model identities are logged. Without AI, supported
deterministic checks still run and reports state the analysis limitations.

For Codex with an Ollama fallback, put these settings in `~/.vulnora/.env`:

```dotenv
LLM_PROVIDER=codex
VULNORA_DEFAULT_PROVIDER=codex
VULNORA_MODEL_FALLBACK=local
VULNORA_LOCAL_BASE_URL=http://127.0.0.1:11434/api
VULNORA_LOCAL_MODEL=your-installed-model
```

For a local primary, select Ollama in Settings or set `LLM_PROVIDER=local` and
`VULNORA_DEFAULT_PROVIDER=local`. API providers remain available through Settings;
**Change API Key** masks entry and credentials are redacted from logs.

Explicit choices saved in Settings take precedence over inherited startup defaults.
API credentials are stored in the dedicated configuration directory with owner-only
Unix permissions; Windows access is limited to the current user, SYSTEM and administrators.
This protects local files through operating-system permissions; the settings file is
not an encrypted credential vault.

Graceful exit unloads the held model and waits for removal from Ollama's running
list. After a force-kill, use `ollama stop your-installed-model` if it remains
loaded. Other installed models are left alone.

## Checks and development

```bash
npm test
npm run typecheck
npm run build
npm run lint
npm run arsenal:doctor
npm start -- --help
```

Tests cover localhost HTTP/TCP behavior, interruption, durable recovery, safe
replay, deduplication, scope, terminal navigation/redraw, reports and provider
lifecycle. Installed-provider and terminal checks are tracked separately in the ledger.

Optional headless commands include `status`, `test`, `models`, and `setup`.
The library, backend API and MCP integration remain available for existing callers.

## License and design attribution

AGPL-3.0-or-later; see [LICENSE](LICENSE). Adapted logo composition, indexed palette
and terminal design derive from the inspected
[VoidAccess source](https://github.com/KatrielMoses/voidaccess). Its MIT notice and
inspected revision are recorded in the milestone ledger and
[third-party notice](THIRD_PARTY_NOTICES.md).
