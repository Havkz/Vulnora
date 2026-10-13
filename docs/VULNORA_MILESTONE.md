# Vulnora implementation and acceptance ledger

## Scope and recoverable baseline

Implement the complete user milestone: rebrand the existing CLI, preserve the working
website/API scanner and reports, introduce persistent projects and operation-level
recovery, safe pause/shutdown, adaptive scanning, and authenticated CLI/local providers.
The user's later instruction replaces renaming the existing GitHub repository with
a **new private repository**, https://github.com/Havkz/Vulnora.

- Baseline: `e558cc9`, tag `vulnora-baseline-20261013-e558cc9`.
- Development: `feature/vulnora`; original repository remote retained as `tempest`.
- Baseline Windows regression: 49 suites, 549 passed, 16 POSIX-only skipped; 11 preflight checks passed.
- No target scans are authorized by this UI milestone; integration checks use local fixtures.

## Source analysis

Existing responsibilities:

| Concern | Existing source and intended integration |
| --- | --- |
| CLI and logging | `src/cli.ts`, `src/live-log-policy.ts`: replace interactive presentation, retain commands and detailed event categories |
| Scanner | `src/index.ts`: command tick, task dispatch, phase advancement, deterministic coverage recovery |
| Tasks and phases | `src/mission/index.ts`: MissionControl/TaskQueue; extend with validated snapshot restoration |
| Individual execution | `src/operators/index.ts`, `src/agent/index.ts`: task controller, AI context and tool loop; checkpoint before and after tools |
| Evidence | `src/evidence/index.ts`, `src/orchestrator/evidence-store.ts`, `src/orchestrator/tool-orchestrator.ts`: preserve findings and dedup evidence across restart |
| Reports | `src/analysis/index.ts`, `src/terminal-report.ts`, `generate_report`: retain data/export and gate display on Enter |
| Providers | `src/llm/index.ts`, `src/agent/local-agents.ts`, `src/llm/ollama-session.ts`: supported CLI invocation, cancellation, local fallback lifecycle |
| Configuration | `src/config/index.ts`, launch/setup scripts: safe namespace migration and secure local settings |
| New persistent project layer | versioned atomic project/checkpoint records; no in-memory-only resume promises |
| New terminal layer | central theme, one renderer, keyboard and resize ownership, append-only full event history |

VoidAccess source inspected from https://github.com/KatrielMoses/voidaccess at
`0dd59daad2dfe48ec5843726a672138d28a67d6e`:

- `voidaccess_cli/main.py`: 11-row circular block/shade logo, indexed colors 141
  (`#af87ff`) and 183 (`#d7afff`), bright-white center word, shared-axis centering.
- `voidaccess_cli/display.py`: magenta panel border/title, one row per event-driven
  stage, grid padding `(0, 1)`, panel padding `(1, 2)`, 8 Hz live refresh.
- Statuses: pending `·`/grey50, active braille spinner/cyan, success `✓`/green,
  failure `✗`/red, skip `↷`/yellow; detail grey62, white active text.
- Spinner: `⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏`.
- Actual upstream navigation is Typer subcommands and Rich prompts, not an arrow-key
  main menu. Implement the explicitly requested arrow menus with the same tokens.
- Upstream license: MIT, Copyright (c) 2026 VoidAccess Contributors; retain notice
  for adapted logo/style composition. Existing project remains AGPL-3.0-or-later.

## Milestones (commit and push each verified intermediate state)

1. **Preparation**: baseline, private repository, source analysis and this ledger.
2. **Theme and branding**: exact reference tokens/logo, versioned configuration
   migration, application/package/command/docs branding and secure compatibility.
3. **Durable recovery**: atomic project records, mission/task/AI/tool checkpoints,
   dedup evidence, interrupted non-idempotent work held for inspection, saved reports/logs.
4. **Interactive CLI**: real four-row startup, three-item menu, name/target/READY,
   project picker, live logs/footer, pause/settings/resume, save-and-quit, Enter-gated reports.
5. **Behavior and providers**: bounded measured Auto/Stealth/Aggressive presets,
   deterministic degradation, installed Ollama model discovery/inference, supported
   authenticated Codex/Claude invocation, provider status and secure API settings.
6. **Acceptance and installation**: regression/integration/terminal snapshots,
   real Windows/WSL `vulnora` launch, model unload, documentation and repository audit.

## Required completion evidence

All entries below remain unproven until the corresponding tests or real runtime checks pass.

| Requirement | Authoritative acceptance evidence | State |
| --- | --- | --- |
| Private GitHub repository and recoverable history | GitHub visibility/default branch/remote SHA and baseline tag | verified preparation |
| Vulnora command/package/references, no old UI branding or emojis | package bin execution, source audit, installed shell command | pending |
| Legacy config/projects/history/reports preserved | migration fixtures plus actual before/after hashes; no credential output | pending |
| Reference logo/colors/shared theme across all screens | reference-derived snapshots at wide/narrow terminal widths | pending |
| Exactly four real startup rows and animated fixed Starting | renderer event tests, real startup success and failure transcripts | pending |
| Three-item menu; arrows/Enter/Esc/Ctrl+C | keyboard-driven terminal integration tests | pending |
| Name and URL/IP/IPv6/hostname validation, original input visible, READY wait | validation and UI flow tests; no request before confirmation | pending |
| Project list metadata and completed project inspection | persistent store restart tests and CLI project picker flow | pending |
| Partial operation/queue/parameters/results/backoff/AI/report/log recovery | checkpoint restoration and forced-kill/restart fixture scans | pending |
| Prevent unsafe duplicate non-idempotent work | interrupted write-request test proving no automatic retry | pending |
| Full detailed event history, event-driven live UI and fixed footer | log preservation assertions, redraw/resize snapshots | pending |
| Esc safe pause and Settings without progress loss | in-flight cancellation/quiescence and resume integration tests | pending |
| Ctrl+C durable checkpoint/log flush/resource and terminal cleanup | subprocess interruption/repeated signal tests | pending |
| Completion waits for Enter, existing generate_report and all export content | report gate integration test and stored report round-trip | pending |
| Auto adapts to actual latency/errors/429/stability with hard bounds | local server scenarios; deterministic execution without AI | pending |
| Stealth low impact and Aggressive bounded throughput | pacing/concurrency/retry ceiling tests, no monitoring evasion | pending |
| Ollama installed model discovery/selection/inference and fallback | local API contract tests and real installed model verification | pending |
| Claude/Codex documented authenticated CLI, no credential file reads/writes | official-interface checks and subprocess tests, runtime where installed | pending |
| Provider/model/API settings, secure keys, truthful fallback logs | settings persistence/redaction/cancellation/availability tests | pending |
| Regression tests/build/lint, documentation and working installation | final fresh run outputs and installed-command integration gate | pending |

## Recovery guarantees to implement honestly

Persist safe tool boundaries and the exact queued AI tool batch/context. A live TCP
request cannot resume inside a packet exchange. Restart an interrupted read-only
request only when safe; hold interrupted state-changing work for explicit review.
External scanners restart their unfinished process when they have no supported
checkpoint format; retain completed evidence and never claim protocol-level continuation.
Pause stops scheduling first, then drains/cancels work according to capability before
offering a resumable menu. A completed project opens its results without starting a scan.

## Progress

- Preparation committed and pushed as `51486c4`.
- Shared VoidAccess tokens, logo snapshot and application/config namespace implementation
  are wired into CLI/setup/report formatting. Legacy library imports retain aliases.
- Migration tests cover preservation, non-overwrite, exclusion of provider credentials,
  repeated migration, and hash records; files publish only after a flush.
- Branding intermediate regression: 50 suites, 552 passed, 16 POSIX skipped, 11 preflight
  checks passed; build passes; lint has zero errors and 195 existing warnings.
- Installer no longer copies Codex credentials or modifies its config. Supported
  CLI availability/authentication and installation remain to be verified in milestone 5/6.
- Persistent projects, granular recovery, new interactive UI, adaptive scanning and
  installed command remain pending. The existing installed runtime has not been replaced.
- Project-store foundation adds original-input target validation (URLs, IPv4/IPv6,
  hostnames), atomic flushed JSON records, full append-only event journals, and
  non-destructive truncated-tail recovery. Focused checks: 24 project cases plus 3
  theme/migration cases pass. Scanner checkpoint integration remains pending.
- The Windows legacy launcher is backed up and pinned to its installed baseline
  during development; a fresh `tempest --help` invocation still passes.
- GitHub run `38417343283` passes on Windows and Ubuntu after canonicalizing the
  Windows agent fixture's short temporary path; actual subprocess checks remain intact.
- Agent checkpoints retain exact pending tool calls, full model context, completed
  steps/findings, dedup state and cumulative budgets. Persistence is awaited before
  execution; interrupted POST/unknown tools are held, and checkpoint failures bypass
  task decomposition. Nine focused recovery cases pass, including disk round-trip of
  a partial batch. Full regression: 52 suites, 585 passed, 16 POSIX skipped, 11
  preflight checks passed. Whole scanner/project/UI recovery is still pending.
- Whole-engine snapshots now retain missions, queues, targets, evidence, budget
  charges, network/backoff observations, coverage recovery, operator IDs/settings,
  and coordination state. Restoring is validated before mutation and preserves the
  original project scope. Local OS-owned leases prevent concurrent project execution.
- Real subprocess kill/restart checks cover a completed GET followed by an interrupted
  GET, and a POST whose completion receipt was persisted before the agent consumed it.
  Completed work is reused without another request; a POST with no completion receipt
  remains blocked. Request budgets are saved before execution and are never reset by restart.
- ProjectSession connects atomic records, full event journals, safe in-flight drain,
  report generation on explicit request, and reopening completed reports. Scan progress
  now preserves multiline content without the previous 2000-character cut; the durable
  journal preserves history beyond the in-memory window.
- Focused recovery/session checks: 29 pass. Interactive keyboard/terminal integration,
  decomposed-task recovery, adaptive presets, provider readiness and final installation
  still need acceptance work; the new interactive CLI is not yet installed.
- Whole recovery intermediate regression: 54 suites, 605 passed, 16 POSIX skipped,
  and 11 preflight checks passed. Build passes; lint has zero errors and the 195
  existing warnings. GitHub run `38419615223` verified the preceding agent milestone
  on both Windows and Ubuntu; the whole-recovery commit has its own CI gate.
