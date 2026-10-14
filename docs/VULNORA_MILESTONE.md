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
| Original shield/logo and steel-blue shared theme (user override on 2026-10-14) | shared theme and snapshots at wide/narrow terminal widths | pending |
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
- Whole recovery was committed/pushed as `8f06ff0`. Its GitHub run `38424374876`
  did not start either runner: GitHub reports failed account payments or an exhausted
  spending limit. No billing settings were changed. Independent clean-install WSL
  validation of this exact commit passes build, lint (0 errors), 617 tests with 4
  Windows-only skips, and 11 preflight checks; Windows passed 605 with 16 POSIX skips.
- Terminal renderer is being connected next. It owns keyboard input, 8 Hz status
  animation, changed-row repaint, terminal resize, masked secret input and restoration.
  Its Unicode width helper reuses the already-installed `string-width` dependency.
  Stream-driven renderer tests are not a claim that the installed interactive CLI is ready.

- Renderer foundation validation: 55 Windows suites, 617 passed and 16 POSIX skips;
  11 preflight checks passed, 12 keyboard/rendering cases and two terminal snapshots.
  Build/typecheck pass; lint has 0 errors and 194 existing warnings. No new default
  menu or installed alias is claimed until application/runtime integration passes.

- Project sessions now enforce the exact selected host rather than admitting unrelated
  loopback/private ranges or subdomains. The scope is restored on every project open.
  Legacy library scope defaults remain compatible. Recon bootstrap preserves original
  URL schemes, ports, paths and IPv6 addresses; DNS/port tools receive only the host.
  Validation: 56 Windows suites, 626 passed, 16 skips, 11 preflight checks; build,
  typecheck and lint (0 errors, 194 warnings) pass.

- The new default CLI now connects the themed menu to persistent name/target drafts,
  explicit READY confirmation, the real ProjectSession, resumable project metadata,
  scrollable untruncated logs, a completion report gate, and full Markdown export.
  The obsolete operation/menu implementation was removed; existing setup/status/test/
  models commands remain available through a separate command module.
- Integrated keyboard cases cover READY without opening a scanner, saved partial input,
  actual scheduler pause/resume and repeated interrupts, completed report reopening,
  and report generation only after explicit Enter. A scheduler resume bug found by
  integration was corrected in ProjectSession.start().
- A real Linux kernel PTY check at 80x30 and 24x12 passes startup/menu, original-target
  READY without scan, editing/back navigation, settings, terminal restoration and Ctrl+C.
  The installed 30B Ollama model stays loaded through the session and unloads on exit.
  Ollama acknowledges unload asynchronously; shutdown now also confirms removal from
  /api/ps. Latest live transcript: /home/tempest/.vulnora/validation/ui-preview-a0aase2z.
  This validates the compiled preview in WSL, not the final installed Windows alias.
- New settings retain local-model and installed-agent choices across process restarts.
  Behavior selection is persisted but retuned effective presets are still pending.
  Provider authentication/inference validation, deterministic fallback, decomposed
  task recovery and final deployment remain outstanding. No completion is claimed.

- Integrated CLI intermediate validation: 59 Windows suites, 637 passed and 16
  POSIX skips; 11 preflight checks passed. Build/typecheck pass; lint has 0 errors
  and 192 existing warnings. Tests cap worker concurrency at four; the Windows CLI
  detection/dispatch case allows its two separately bounded subprocess deadlines.
  Full live terminal/model checks pass after unloading confirmation was added.
  Hosted GitHub runs for renderer/scope still fail before runner startup due to billing.

- Clean-install Linux validation of committed CLI milestone 6dddbf4 also passes:
  59 suites, 649 tests passed and 4 Windows skips; 11 preflight checks, build and lint
  pass. Validation directory: /home/tempest/.vulnora/validation/6dddbf4.qEm0qu.

- Codex/Claude availability now asks official CLI authentication status instead of
  inferring a working login from credential-file presence. Status output is reduced to
  booleans; no auth contents or account identifiers are read, copied or logged.
  Version/auth subprocesses close stdin, hide Windows helper windows and have deadlines.
- WSL connector resolution prefers installed Linux CLIs over inherited Windows npm
  wrappers. A real check resolves /home/tempest/.local/bin/codex v0.162.1, confirms its
  existing login through login status, requests an offline base64_decode tool through
  LLMBackbone, and executes it successfully: CODEX_NATIVE_TOOL_CALL_OK. Claude is
  currently absent on Windows; its supported status paths have controlled CLI tests.
- Authentication milestone checks: 60 Windows suites, 642 passed and 17 POSIX skips;
  11 preflight checks passed. Build/typecheck and focused lint pass. Startup readiness,
  streaming transport and fallback ownership still need integration/acceptance work.
  References: https://developers.openai.com/codex/cli/reference and
  https://code.claude.com/docs/en/cli-reference (official sources checked 2026-10-13).

- The Codex backbone now reuses the authenticated local-agent transport instead of
  maintaining another subprocess implementation. Both connectors remove injected
  application API keys; Codex runs in an ephemeral empty directory with read-only
  sandbox/approval-never, and Claude has native/MCP tools disabled and no CLI history.
- Official JSON progress is decoded incrementally (including split UTF-8), redacted
  by the backbone and retained in the project journal. Cancellation/deadlines stop
  the child and await its close before deleting temporary files; output is bounded
  and semantic CLI errors reject even when the process exits zero. The real native
  WSL Codex tool-contract check still passes: CODEX_NATIVE_TOOL_CALL_OK.
- Transport regression: 61 Windows suites, 653 tests passed, 17 POSIX skipped,
  11 preflight checks passed; build passes. A WSL-specific test inherited WSL flags
  while asserting ordinary POSIX PATH precedence; that fixture now explicitly
  clears those flags. Clean Linux validation is repeated for this corrected milestone.
  Startup provider validation, effective presets, decomposed recovery and deployment
  remain outstanding; Claude live inference cannot be checked without an installation.

- Corrected transport milestone 051db05 passes clean-install Linux build/lint
  (0 errors), all 61 suites with 667 passed/4 Windows skips, and 11 preflight checks.
  Validation directory: /home/tempest/.vulnora/validation/051db05.MzFTnP.
- READY target edits now persist in a finally block even when Ctrl+C interrupts
  the prompt. An explicitly empty draft remains empty when reopened. Buffered edit
  characters received before interruption are saved, while queued Enter/actions
  and input received after interruption are never executed.
- READY edit validation: 61 Windows suites, 656 passed/17 POSIX skips, 11 preflight
  checks, build and focused lint pass. Real Linux PTY (80x30 and 24x12) confirms
  the interrupted edit is persisted, READY performs no scan, terminal state restores,
  and the installed 30B model remains held then unloads on Ctrl+C. Transcript:
  /home/tempest/.vulnora/validation/ui-preview-wddj135e/terminal-transcript.ansi.
  GitHub run 38459924921 still has runner_id=0/no job steps; hosted billing remains
  an external validation limitation. The final installed Vulnora alias is pending.

- Interactive startup now owns a ProviderSession separate from the terminal/scanner.
  It queries installed Ollama models without downloading, holds the selected model,
  and validates actual inference independently of the selected primary. Codex/Claude
  version/authentication status is checked through their official CLI commands before
  inference; API-key/model changes revalidate connectivity while the scanner is paused.
- The interactive fallback chain is selected primary, validated installed Ollama,
  then deterministic evidence-only operation. Startup failures stay visible and allow
  Settings/saved reports. Provider switching includes actual provider/model fields;
  the live view displays the active provider rather than calling every response Codex.
- Deterministic execution performs real supported checks, preserves tool findings and
  interrupted batches, and states that AI analysis is unavailable. It does not return
  mock model answers. Controlled tests perform a real scoped HEAD request, restore
  a partial batch without another plan, and reopen a complete report without AI.
- Native planner calls disable their independent tools: Codex disables shell/exec,
  apps/plugins/hooks, browser/computer access, web search and configured MCP servers
  through invocation overrides. Claude uses safe mode, empty native tools/MCP denial,
  retaining its normal existing authentication; bare mode would require an API key.
  Existing provider authentication/configuration files are never edited or copied.
- Real installed-runtime evidence: VULNORA_REAL_PROVIDER_READINESS_OK confirms Codex
  and huihui_ai/qwen3-coder-abliterated:30b both infer successfully; forced Codex failure
  produces VULNORA_REAL_OLLAMA_FALLBACK_TOOL_CALL_OK and the harness executes the
  requested base64_decode. VULNORA_REAL_PROVIDER_RELEASE_OK confirms model unloading.
  The restricted native Codex connector also passes CODEX_NATIVE_TOOL_CALL_OK.
- The Linux PTY preview remains green at 80x30/24x12, including READY without scan,
  partial edit persistence and model holding/release. Latest preview transcript:
  /home/tempest/.vulnora/validation/ui-preview-y77n6cjh/terminal-transcript.ansi.
  Same-model settings revalidation reuses the held session; only a changed model
  unloads its predecessor before loading the replacement.
- Effective adaptive presets, decomposed-task recovery, final alias/deployment,
  remaining documentation/theme acceptance and secure-setting validation still need
  work. Hosted CI billing remains blocked; Claude live inference is unavailable on
  this machine. Official sources checked: https://developers.openai.com/codex/config-reference
  and https://code.claude.com/docs/en/cli-reference (2026-10-13).
- Provider milestone Windows validation: 63 suites, 673 tests passed/17 POSIX skips,
  11 preflight checks passed; build and lint pass (0 errors, 192 existing warnings).
  Clean-install Linux validation runs against the committed snapshot before this
  intermediate milestone is considered portable. No final-installation claim is made.
- Committed provider milestone 87dbb61 also passes clean-install Linux build/lint
  (0 errors), all 63 suites with 686 passed/4 Windows skips and 11 preflight checks.
  Validation directory: /home/tempest/.vulnora/validation/87dbb61.w1vqfm.

- Decomposed work now persists inside its parent task: planning failure/reason,
  ordered children, completed results, nested agent/tool-batch checkpoints and the
  remaining cooldown. Children retain their parent's mission, phase, role and target.
  The complete stored tree is validated before any restored child executes.
- One root cancellation controller owns the full tree; the operator remains busy
  while children execute or wait. Completed children are skipped on resume, planning
  interruption resumes planning rather than repeating parent execution, and unsafe
  replay/checkpoint failures still bypass decomposition. Recovery is bounded to three
  levels (at most 84 children); configured smaller retry ceilings are respected.
- A real scanner subprocess kill/restart test now covers a decomposed pair of HTTP
  requests: first completed response is preserved without another request, interrupted
  second GET is safely retried, its prior budget charge remains, and the original
  saved queue finishes. Unit checks cover writer failure, malformed child contracts,
  shared cancellation, recursion limits and cooldown restoration.
- Child progress refreshes its root dispatch's activity timestamp so a working
  decomposition is not mistaken for a silent/wedged root operation. Existing task,
  tool, finding and cooldown events remain available.
- Decomposition milestone Windows validation: 64 suites, 681 passed/17 POSIX
  skips, 11 preflight checks, build/typecheck and focused lint pass. The CLI
  cancellation fixture now waits for complete invocation metadata before asserting
  termination; its PID file can become visible before the next file is fully written.
- The committed decomposition snapshot also passes Linux: 64 suites, 694 passed/
  4 Windows skips, 11 preflight checks, from the isolated validation directory
  /home/tempest/.vulnora/validation/1f71557.lzLZkV.
- Effective project modes now set actual operator dispatch ceilings and a shared
  per-host HTTP/TCP/DNS scheduler. HTTP slots cover body consumption, retries are
  limited to bodyless GET/HEAD, extra requests are charged before sending, and
  checkpoint failures stop execution even when a handler catches the error.
- Response latency, 429/5xx and transport failures reduce concurrency and increase
  pacing/backoff; stable observations restore the bounded preset. Persisted policy
  includes outstanding Retry-After, adaptive state and last admission. Mode changes
  preserve scope, operator pool capacity, accumulated budgets and backoff.
- External scanners use an exclusive host lane with supported rate/thread/delay/
  timeout/retry options. Native CLI help was checked for installed tools, including
  Naabu's pass-count semantics and Dalfox's current workers/backoff/bypass options.
  Opaque subprocesses cannot be retuned per response from outside; subsequent work
  adapts after completion. See docs/SCAN_MODES.md for exact limits and boundaries.
- Mode milestone Windows validation: all 65 suites, 700 passed/17 POSIX skips,
  11 preflight checks; build/typecheck and lint pass (0 errors). Timing tests also
  simulate slow durable writes: request starts remain paced after checkpointing,
  cancellation stops queued work, and bodies retain their concurrency slots.
- Committed mode snapshot 4665b22 passes clean-install Linux build/lint (0 errors),
  all 65 suites with 713 passed/4 Windows skips and all 11 preflight checks.
  Validation directory: /home/tempest/.vulnora/validation/4665b22.ldle58.
  The TCP timing fixture measures client initiation; server accept notifications
  can arrive after the client has completed its handshake, particularly on Linux.
- README now documents the actual website/API CLI, persistent projects, controls,
  reports, adaptive modes and primary/local/deterministic providers. Old unrelated
  cloud/mobile/binary marketing, download examples and unsupported benchmark
  claims were removed. Final installed-command validation remains explicit.
- Live logs now use the shared status/severity palette and cache their wrapped rows.
  Unchanged refreshes reuse existing rows; appended events are wrapped once and
  resizing preserves the current event/character reading anchor. Detailed event
  text and the durable journal are unchanged.
- Interactive reports now use the existing terminal Markdown formatter with the
  actual surface theme and ANSI-preserving wrapping. Fenced technical evidence is
  treated literally instead of interpreting payload Markdown. Document wrapping is
  cached until terminal width changes. The already-installed wrap-ansi 8.1.0 is
  declared directly; no new runtime package or formatter implementation is added.
- The shared report export no longer truncates each evidence item to 100 characters.
  It retains complete redacted evidence, timestamps/metadata, CWE classifications
  and references, with fences chosen to contain embedded backticks safely.
- Presentation/report intermediate Windows validation: 65 suites, 703 passed/
  17 POSIX skips, 11 preflight checks; build/typecheck and lint pass (0 errors).
  Focused interactive tests also verify stable wrapping, severity colors, resizing
  without losing the reading anchor and complete journal content.

- Committed presentation snapshot e1eea8e also passes clean-install Linux build/lint
  (0 errors), 65 suites with 716 passed/4 Windows skips and 11 preflight checks.
  Validation directory: /home/tempest/.vulnora/validation/e1eea8e.ou8qEp.
  Real Codex/Ollama readiness, forced local fallback and model release pass; the
  kernel PTY preview passes at 80x30 and 24x12, including READY without scan,
  interrupted edit persistence and terminal restoration. Preview transcript:
  /home/tempest/.vulnora/validation/ui-preview-kaeisw0c/terminal-transcript.ansi.
- Saved provider, model and API-key choices now survive stale startup environment
  defaults and reopening. Local fallback uses the same resolved configuration,
  including an explicitly saved bearer. Environment credentials are not persisted.
- Configured opaque credentials are redacted from API errors, stacks and request
  events; HTTP status remains available so permanent authentication failures are
  not retried. Overlapping credentials are scrubbed longest first.
- Configuration writes use mode 600 and the dedicated Unix directory mode 700.
  On Windows, existing credential files and atomic replacements are protected by
  directory/file ACLs granting only the current user, SYSTEM and administrators.
  This is permission-protected local storage, not an encrypted vault. Provider CLI
  authentication files remain untouched. Real Windows ACLs are asserted in tests.
- Settings/security milestone Windows validation: 66 suites, 708 passed/17 POSIX
  skips, all 11 preflight checks; build/typecheck and lint pass (0 errors).
  Local bearer aliases are now tested through actual configuration resolution;
  the resize fixture waits until queued navigation finishes before checking its
  reading anchor. Linux validation and final deployment remain separate gates.
- Settings/security commit 1ddb04a also passes clean-install Linux build/lint
  (0 errors), all 66 suites with 721 passed/4 Windows skips and 11 preflight checks.
  Actual Linux file/directory permissions are asserted after saved-key updates.
  Validation directory: /home/tempest/.vulnora/validation/1ddb04a.VVJQo4.
- Windows setup now reuses the existing Kali distribution and Linux provider user,
  deploying committed releases under ~/.vulnora/releases/<revision>. Strict tool
  checks, build and non-overwriting data migration precede runtime publication.
  Original application files and native provider credentials are left in place.
- The Linux launcher resolves its own release directory and respects saved/default
  provider configuration. Windows uses the runtime manifest, starts loopback Ollama
  only when needed, stops only its own service, and accepts normal Ctrl+C exit 130.
  Model loading/unloading remains owned by ProviderSession; no hardcoded model is
  unloaded by the wrapper. A failed provider no longer blocks all startup before UI.
- The alias installer selectively replaces old profile functions and the CMD wrapper,
  backing them up first. Actual installed-launch validation remains required before
  applying these aliases. Windows launcher lifecycle fixtures and shell syntax pass.
  Regression: 67 Windows suites, 709 passed/18 skips, 11 preflight checks; build and
  focused lint pass. The Linux launcher has its own actual-process fixture.
- Release 6f3ada1 passes clean-install Linux build/lint (0 errors), all 67 suites
  with 722 passed/5 platform skips and 11 preflight checks. Validation directory:
  /home/tempest/.vulnora/validation/6f3ada1.6kGZOf.
- The committed release is actually installed in Tempest-Arsenal at
  /home/tempest/.vulnora/releases/6f3ada1b84f485c8ec3b7e71cc3832b478833d87.
  Strict readiness is 23/23. Before/after SHA256 verifies the original application
  package, CLI and legacy environment remain unchanged. Migration retains Linux
  legacy settings and fills missing configuration from Windows without overwrites.
- Live checks now import the installed release, not the checkout: Codex and the
  installed 30B model pass real inference; forced Codex failure yields a real local
  tool call; release confirms the held model unloads. A kernel PTY at 80x30/24x12
  verifies installed-launch READY without scan, partial edit persistence, Settings,
  model holding/release and terminal cleanup. Saved transcript:
  /home/tempest/.vulnora/validation/ui-preview-o0o3mryu/terminal-transcript.ansi.
- Alias installation is applied and verified: fresh PowerShell 7, Windows PowerShell
  and CMD all execute `vulnora --help` successfully. Old profile functions and the
  old CMD wrapper were backed up to
  C:\Users\User\.vulnora\backups\aliases-20261014-185154-3748; the CMD wrapper is
  replaced and the preserved Tempest runtime files remain intact. No Ollama service
  remains after the owned validation service exits.
- Full goal completion is still unproven: the visual panel/spacing and narrow-screen
  prompt acceptance, final branding/data-recovery audit, and physical Windows Terminal
  live scan/report flows remain outstanding. Claude live inference is unavailable
  without an installation. GitHub run 38600463109 has runner_id=0 and no executed
  test steps; its annotation confirms failed account payments or a spending-limit
  restriction. Hosted CI remains an external validation gate; billing is not changed.
- Startup/live/READY status views now use the reference's rounded magenta panel,
  padding (1, 2), white stage labels, status-colored glyphs and grey details. The
  startup table retains the reference grid indentation. At tiny heights the border
  is omitted so all four actual initialization rows remain visible. Snapshots cover
  80x30, 40x24 and 24x12; minimum 16x8 and unsupported resize dimensions are tested.
- READY reserves its confirmation rows and pages the full original target when it
  exceeds the viewport. Resume metadata exposes full name, target, creation/activity,
  status and progress with independent paging. Selected choices and document titles
  no longer write into the last terminal cell and trigger unintended wrapping.
- Live scans reserve their completion hint and shortcut bar even with long names,
  URLs or model IDs. Complete log rows and their reading anchor remain preserved;
  full error text remains accessible in the log viewport. Narrow 24x12/16x8 flows
  assert bounded rows/cell widths, no scan before confirmation and no report before
  Enter. Installing a new release now backs up the previous runtime manifest.
- Panel/narrow-view milestone Windows validation: all 67 suites, 716 passed/18
  platform skips, 11 preflight checks, build/typecheck and focused lint pass.
  Installed-release/Linux/terminal checks remain separate evidence gates.
- Committed UI release 4c77748 passes clean-install Linux build/lint (0 errors),
  all 67 suites with 729 passed/5 skips and 11 preflight checks. Directory:
  /home/tempest/.vulnora/validation/4c77748.jfpr8i. The release is installed under
  /home/tempest/.vulnora/releases/4c777482cd3f84fc4b2c9d20cba4c7a3191e6ec5.
- Its real kernel PTY check passes at 80x30 and 24x12, including provider startup,
  model hold/release, READY without scan, interrupted edit persistence and terminal
  restoration. Transcript: /home/tempest/.vulnora/validation/ui-preview-8dusgt3d/terminal-transcript.ansi.
  Legacy package/CLI/environment hashes still match their pre-installation snapshot.
- Documentation audit found obsolete default REPL/preset, dashboard and cloud
  fallback descriptions in FEATURES.md/WHITEPAPER.md. Those current-surface sections
  now describe the actual projects, source-derived theme, local fallback and secure
  settings. Retained library/research documentation is explicitly scoped separately.
  Physical Windows Terminal live scan/report and final requirement-by-requirement
  audit remain outstanding; this is not a full-goal completion claim.

### User correction: provider notice and original visual identity (2026-10-14)

- Explicit Settings selections already override inherited startup defaults. Removed
  the obsolete environment-override notice when choosing installed Codex/Claude;
  the normal availability check still validates the selected provider immediately.
  The interactive regression reproduces startup `codex` -> installed CLI `codex`
  and checks both the saved effective configuration and provider preparation.
- User superseded the copied reference logo/colors requirement: original shield
  wordmark with steel-blue/cyan accents replaces the circular mark and purple
  palette. Navigation, panel structure and status meanings retain existing behavior.
  Narrow terminals use the compact wordmark; snapshots cover bounded layouts.
  Reference attribution remains for retained panel/spacing/status conventions.
- Windows validation: 67 suites, 717 passed/18 platform skips; all 11 preflight
  checks, TypeScript build and focused lint pass. Graph regenerated after edits.
  Installed release/provider-switch verification follows this source milestone.
