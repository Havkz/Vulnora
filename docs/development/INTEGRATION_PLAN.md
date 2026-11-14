# Web assessment integration — working ledger

This is an implementation ledger, not a claim that the full integration is complete.
The existing terminal theme, rendering components and visual identity are invariants.

## Reference snapshots

Source inspected directly from read-only checkouts:

| Project | Revision | License | Relevant observations |
| --- | --- | --- | --- |
| [Strix](https://github.com/usestrix/strix) | `a0f8ea2cd379c4bf56e665d3db2ba8a4f7c0683c` | Apache-2.0 | Separate transient errors from guardrail errors (`core/execution.py`); persist session history and tool output; explicit coverage records and report evidence references. |
| [NeuroSploit](https://github.com/Red-Team-Leaders/NeuroSploit) | `0234a9593603fcce5abf54c75c2b362ea9175ba4` | MIT | Rust harness; finite provider retries, no repeated quota/auth retries (`crates/harness/src/pool.rs`); deterministic probing before specialist work; findings can remain needs-review. |

Concepts are reimplemented within Vulnora's TypeScript architecture. No reference code or prompts have been copied. Reference analysis is still in progress; the table does not imply every relevant module has been reviewed.

Avoid transferring Strix's private subscription-backend authentication path; use the installed official Codex CLI. NeuroSploit's text-token receipt heuristic and model voting are insufficient empirical proof: Vulnora must ground verification in captured requests, responses and evidence identifiers.

## Requirements and evidence still needed

| Workstream | Current evidence / gap | Completion evidence |
| --- | --- | --- |
| Reference review | Initial architecture, routing, sessions, coverage and report source reviewed. Browser/proxy/auth, coordination, CLI and report implementation need deeper comparison. | Source-path-based gap analysis covering all relevant subsystems and licenses. |
| Provider routing | Central policy implemented in configuration, TUI and `fallback` CLI; session no longer injects its own ladder. Structured refusal fields, finite retries, audit and actual-model cleanup covered by targeted tests. | Direct `run` overrides are integrated; the streaming helper now shares central policy and has loopback transport coverage; workstation validation remains. |
| Model configuration | Existing Codex/Claude CLI model and reasoning selection, Ollama discovery/manual endpoint, lazy lifecycle. | Same options in saved configuration, TUI and direct CLI; installed Codex preferred on fresh setup; actual active model shown. |
| Direct CLI | `run <url>` and resume share ProjectSession, with intensity/provider/model/reasoning/fallback, scope/excluded-host/tool/rate overrides, transcript output and Markdown reports. Provider tests isolate the selected provider; local model listing queries the actual endpoint. | Versioned run profiles and Markdown/JSON output flags are integrated; complete workstation validation and remaining end-to-end checks. |
| Scope and load | Host/tool exclusions and rate ceilings persist with matching checkpoints; native HTTP redirects/DNS queries recheck host rules; TUI READY rules editor and CLI share validation. | Destructive-action controls, browser enforcement and independent external-scanner/template egress require implementation/verification; entry-target validation is not a complete containment boundary. |
| Web surface | Existing HTTP, TLS, headers, content/API discovery and external scanners. | Local fixture discovery of links, JS/API endpoints, forms, parameters, auth; bounded browser support where it adds coverage. |
| Vulnerability tests | Existing website arsenal needs capability-by-capability audit. | Controlled positive and negative fixtures for SQLi, XSS, IDOR, SSRF, authentication, access controls and misconfiguration; inconclusive stays inconclusive. |
| Adaptive planning | Existing task orchestration, evidence store and operator board. | Prioritized hypotheses, dependency-aware concurrent work, useful context, no redundant requests, bounded recovery, traceable decisions. |
| Verification and chains | Existing impact-validation gate and findings. | Captured evidence supports each confirmed finding; controlled retests; chains link supported findings without fabricated impact. |
| Persistence | Atomic project records, checkpoint recovery, event journal already present. | New options and evidence survive stop/restart; interrupted side effects require review; corrupted/incomplete state fails safely. |
| Reports | Shared TUI/CLI Markdown/JSON snapshots with findings/evidence/coverage/limitations, literal untrusted text and export-directory selection. | Verify coverage classifications and evidence-grounded chains end-to-end; native Windows artifact checks remain. |
| TUI | Existing new/resume/manage/settings and project views. | Report/export, tool management, help/general/fallback menus use existing components; keyboard and resize tests, unchanged theme. |
| Documentation/release | README currently describes existing development state. | Verified commands, config/help, reference attribution, full required checks, local end-to-end run, committed milestones and installed release. |

## Milestones

1. Central fallback policy and model settings, with routing/audit/config/TUI/CLI tests.
2. Shared direct execution and durable assessment options, reports and menus.
3. Evidence-grounded web/browser/auth testing and adaptive coverage integration.
4. Full local end-to-end validation, documentation, release installation and requirement-by-requirement completion audit.

None of these milestones substitutes for completion of the entire objective.

## Checkpoint — 2026-10-20

- Fallback milestone: TypeScript build passed on Linux ARM64; 50 built-artifact fallback assertions passed.
- Eight focused Vitest suites exercised 135 cases. The one failing provider-lifecycle expectation was updated for cleanup of all used models at exit; the affected provider/TUI suites then passed all 42 tests. An existing TUI startup race was corrected by waiting for the actual running state.
- Changed TypeScript files passed ESLint with no errors (six existing test-style warnings).
- Controlled CI now has one dispatch-only workflow on the designated Windows runner, with genuine Linux checks in `CodexPi-CI`. Workflow invariants and shell syntax checked locally; the workflow has not been executed.
- GitHub repository visibility verified private. Native Windows revalidation, final installation and the remaining integration workstreams are outstanding.
- The Windows test handle did not transfer with migration. The new Linux tests are independent evidence; no claims are made about that interrupted run.

## Checkpoint — 2026-10-27

- Recovered and read the original task attachment from the migrated native transcript; the full objective remains in scope.
- Added headless execution over ProjectSession; graceful cancellation drains/persists and releases its lease, completed runs save reports, pauses and partial coverage return a non-success status.
- Process-local inference/fallback switches reuse saved configuration without modifying it. Explicit local testing no longer prepares or tests the primary Codex provider. Discovery lists installed local models without inference.
- Kept heavy scan-engine imports inside the run action so help, provider testing and settings commands retain their small startup path.
- Targeted Linux verification: 12 direct CLI/provider cases (including real loopback HTTP and a SIGINT subprocess), then 27 lifecycle/settings/provider regression cases and 18 fallback-policy cases passed. These runs overlap; they are not a full-suite or Windows result. Changed files passed ESLint without errors or warnings; new relative documentation links resolve.
- Remaining milestone 2 work includes durable scope/rate/exclusion controls, config-file loading, richer exports and TUI menu integration. This checkpoint is not completion of the overall objective.

## Assessment rules milestone — 2026-10-27

- Shared validated host allow/exclude lists, exact tool exclusions and an integer per-host rate ceiling now persist in project records and engine checkpoints. Mismatched rules prevent resume. Ready-project edits acquire the existing exclusive lease and cannot overwrite started sessions.
- CLI flags and the TUI's `R Rules` editor use the same rules. The original READY layout remains intact, including small-terminal target scrolling. Runtime definitions omit excluded tools; direct calls are blocked. Native HTTP redirects and generated DNS candidates recheck scope.
- Canonical host identity prevents case/trailing-dot/IPv6 spelling variants from bypassing comparisons or managed request pacing. Delay-only external clients use a single worker under explicit caps.
- A real readline reproduction exposed quick Esc+Ctrl+X being emitted as an unnamed meta sequence. The global interrupt handler now recognizes it; direct terminal and menu-flow regressions cover it.
- Eight focused Linux suites passed all 133 cases, including actual loopback HTTP, CLI subprocess cancellation, restart, lease contention and terminal resizing. TypeScript build passed. Changed-file ESLint reported zero errors and 15 warnings; documentation relative paths resolve.
- No native Windows/scanner-template containment result is claimed. External generated destinations, destructive-action policy, browser integration, config-file loading, richer reports and remaining source comparison are still open requirements.

## Configuration and reporting source comparison

- Strix `config/loader.py` ties a model, API endpoint and credential to one provider connection; overriding the provider must not carry a different provider's model/effort. Vulnora run profiles are read-only defaults layered over central settings, with explicit CLI options taking precedence. Unlike Strix's tolerant file loader, malformed explicit profiles fail before starting a scan.
- Strix `report/writer.py` uses atomic artifact replacement, literal evidence fences and structured exports; Vulnora reuses its existing durable project writer and fence renderer. `report/coverage.py` distinguishes runtime observations from agent attestations and explicitly records gaps. Vulnora exports runtime capability statuses/evidence IDs and limitations; these classifications are not independently proven coverage.
- NeuroSploit `crates/harness/src/report.rs` separates confirmed and needs-review findings, includes evidence/auth context and provides Markdown/HTML/Typst output. Vulnora marks each finding using its existing verification gate, exports Markdown/JSON without adding a PDF toolchain, and preserves the terminal design. Its voting/grounding labels are not adopted as empirical proof.
- The prior Vulnora report grouped any two findings on one target into an “Attack Chain.” Such groups now explicitly describe unverified correlations. Actual evidence-backed multi-step chain verification remains a requirement, not a feature claimed by this milestone.
- No reference code was copied; the pinned revisions and licenses above remain the source basis.

## Configuration and report milestone — 2026-11-14

- `run --config` reads bounded UTF-8 JSON profiles, validates every accepted field and uses explicit flags over file defaults. Provider changes drop incompatible profile model/effort defaults. Profiles do not rewrite central settings or accept arbitrary environment/shell configuration.
- `run --output --report-format` and `report <id> --format --output` share the existing durable project writer. The TUI's results view adds `E Export` using existing menu/prompt components. Completed snapshots contain Markdown and versioned JSON; legacy Markdown remains available without fabricated structured data.
- Reports now include completion, scope/rate/exclusions, capability states/evidence IDs, phase outcomes, review status and limitations. Target/model Markdown is escaped while evidence fences preserve literal content. The terminal renderer decodes escaped prose in one pass without interpreting it again as formatting.
- Known secret redaction applies before JSON serialization; coverage is an array so secret-bearing target URLs are values that can be scrubbed, not unredacted object keys. JSON exports contain report data rather than raw checkpoints, credential vaults or model histories.
- Initial targeted runs passed 62 and 87 cases across overlapping suites, covering real CLI subprocesses, loopback provider HTTP, profile precedence, cancellation, persistence and malformed/export-error preservation. Twenty-five local-model discovery/service cases also passed. Subsequent terminal validation exposed test startup races and a short filesystem-test deadline; tests now wait for mission creation and allow the rename/delete transaction adequate time.
- Next evidence gap: `orchestrator/coverage.ts` currently classifies generic successful `inconclusive` outputs as negative checks. Successful reconnaissance observations must be distinguished from inconclusive vulnerability verification, without treating ordinary HTTP responses as failed checks. This needs a focused runtime/coverage change and local fixtures before claiming reliable completeness.
- Windows execution/installation, the streaming fallback helper, browser/auth coverage, external-scanner containment, destructive-action controls and verified chains remain open. The overall goal is not complete.
- Final checks: 32 terminal/menu cases passed after the timing fixes; all four report-redaction cases passed, including tokens in target URLs. The final TypeScript build exited 0 with its exit status saved locally. Changed-source ESLint has no errors (seven existing warnings); renderer files have no warnings. Relative documentation links and `git diff --check` passed. Repository visibility was restored to private and verified through GitHub metadata.


## Coverage verdict repair — 2026-11-14

- Empty or inconclusive validation results no longer become completed negative coverage. Nonempty successful reconnaissance observations remain collected evidence, without claiming a negative security test. Running capabilities also prevent a fully completed mission status.
- Observed GET inputs require positive or explicit negative evidence for each XSS/SQLi check. Inconclusive input checks can be retried, sharing a finite recovery allowance of six calls per observed input across both probes. Least-attempted checks take priority; exhaustion retains the gap, and explicit resume resets the existing recovery counter without deleting evidence.
- Built-in XSS/SQLi probes declare a negative only after usable responses for all checks. Unavailable/empty responses cannot produce a negative verdict. Candidate SQL error evidence from HTTP 500 responses remains available for subsequent verification.
- HTTP method checks now preserve failed requests as incomplete, propagate cancellation and use the existing native HTTP transport for TRACE when the Fetch API cannot send it. Native responses retain a bounded body for reflection inspection and recheck scope. A successful response or advertised method alone is still not a finding.
- Removed the generic “missing/not found” text shortcut for negative verdicts. Other legacy tool-output heuristics and capability aggregation still need review; this repair is not proof of exhaustive scanning, authenticated coverage or verified exploit chains.
- Focused coverage, surface planning, loopback workflow, execution and orchestration tests passed 81 cases. Subsequent checkpoint/report/execution regressions passed 42 cases; the final coverage/workflow run passed 50 cases and the last execution-output run passed 19. These suites overlap. The final TypeScript build passed; changed-file lint has zero errors and 22 style warnings. Windows validation remains outstanding.


## Risk exclusion integration — 2026-11-14

- Reviewed Strix `agents/prompts/scope.jinja`: its prompt distinguishes user scope from untrusted site/tool text, but its broad permission assumptions are not an executable boundary. Vulnora keeps deterministic scope/exclusion checks; those assumptions are not copied. NeuroSploit `crates/harness/src/agents.rs` loads specialist Markdown and categorizes agent roles, not runtime action permissions; specialization alone cannot enforce exclusions.
- Added shared project risk exclusions through `run --exclude-risk`, JSON `excludeRisk`, the existing READY rules menu, engine scope/checkpoints and report metadata. Legacy records normalize without new exclusions; changing saved rules without matching checkpoints remains rejected.
- Exclusions precede approval and execution and remove matching model tool definitions. Managed HTTP/curl writes or nonempty bodies are classified as dangerous; built-in nested HTTP requests also check restrictions. Tool metadata/catalog risks are reused, with conservative untyped-extension handling.
- This is a persisted action-policy control, not proof of arbitrary external scanner/template containment. Template-level controls, browser enforcement and the remaining integration requirements stay open.

- Verification: 73 cases passed across assessment, profile, interactive, approval, CLI subprocess and report suites; 33 subsequent cases passed for nested request denial, reports and website execution. Runs overlap. The initial menu test timed out because it sent Esc immediately followed by a new selection against old transcript text; it now stays in the current menu and has a realistic filesystem deadline.
- Follow-on browser source review: Strix `tools/agent_browser/README.md` and the core/snapshot/session sections of `skills/tooling/agent_browser.md` describe an external `agent-browser` Chromium/CDP CLI, compact accessibility snapshots and per-agent sessions. Vulnora currently has neither that executable nor a browser dependency in this environment. Browser/session/egress integration remains work to implement and validate, not an existing feature.

- Risk milestone final checks: TypeScript build exited 0; changed-file ESLint reported zero errors and 16 existing style warnings. No native Windows result is claimed.


## Static website discovery integration — 2026-11-14

- Reviewed NeuroSploit `crates/harness/src/probe.rs`: its deterministic probe collects bounded form details, script sources, technology/SPA hints and response observations before model recon. Its form parser is string-based and auto-account workflows have separate risks; Vulnora adopts the observation-first concept, not that parser or automatic submission.
- Replaced Vulnora's HTML regex extraction with pinned parse5 8.1.1 (MIT; its entities dependency is BSD-2-Clause). Node has no built-in HTML DOM parser. HTML entities, base URLs, form ownership and real elements now follow parsing semantics; comments/script text do not become forms. No reference code was copied.
- Existing HTTP observations seed a bounded same-origin link/script traversal. Form/query/OpenAPI inputs feed the existing validation planner; script URL literals are unverified hints only. Body/node/page/input limits and unavailable responses preserve incomplete coverage. No script execution or browser claims are made.
- Thirty-five parser/coverage tests passed. The actual loopback assessment now discovers a form on a linked page, reads a linked script without calling its hinted API, and executes both observed-input checks before leaving Scanning; its execution/rule regression run passed 29 cases. Final parser/coverage verification passed all 35 cases; TypeScript build exited 0. Changed-file lint has zero errors and 14 existing style warnings. Windows validation remains outstanding.


## Streaming policy integration — 2026-11-14

- Text streaming and complete responses now share one request lifecycle, finite retry/fallback ladder, classification, audit, provider identity and cancellation path. Existing Codex/Claude progress transport is preserved. Tool definitions use the complete-response path so a text iterator cannot lose tool-call arguments.
- The OpenRouter-compatible transport preserves message context/options and parses SSE comments, multiline events, split UTF-8, finish reasons, usage, refusal fields and in-band errors. Its inactivity timer starts before awaiting headers; malformed/truncated events fail explicitly and early consumer exit closes the transport.
- After any text has been delivered, no replay or model switch occurs. An interrupted stream remains interrupted; refusal classification still runs on completed text, but cannot retract chunks already displayed. Audit records mark partial-output decisions.
- Fifteen streaming cases use a real loopback HTTP server. The final four-suite run passed 71 cases, including existing fallback, key-redaction and CLI tool-calling regressions. TypeScript build exited 0. An early test used a two-second fixture deadline during the Pi's compiler load and retried; the normal fixture now allows ten seconds while the dedicated timeout test remains 100 ms. A model-switch test was corrected to assert the mock adapter's actual reported model separately from the configured selection.
- Reference follow-up: read the first 170 lines of NeuroSploit `crates/harness/src/models.rs` (provider registry and API setup) and first 150 lines of Strix `agents/factory.py` (sandbox tool wiring/output bounding). These partial reads do not establish complete module review. No reference code was copied.
- Next verification issue confirmed in source: `evidence/gate.ts` currently accepts any nonempty output-labelled evidence as verification. `operators/index.ts` carries tool text but loses finding status and evidence-record links. Tool provenance must not substitute for empirically verified vulnerability claims. Browser/auth/verification/chain work and Windows delivery remain open.


## Runtime verification repair — 2026-11-14

- Replaced the live gate's “any output label means verified” shortcut. Verification now resolves captured runtime records and requires successful execution, the same target ID/origin, matching output and finding identity/claim/severity/CVE/CWE, and an explicitly validated result. Observations retain tool provenance without becoming confirmed vulnerabilities.
- Agent/operator conversion now preserves evidence-record links and target address. Vault insertion, edits and checkpoint restoration recompute verification; unsupported legacy stamps and exploitation claims are cleared while evidence remains. Restored target vulnerability state follows the rechecked vault. Verified follow-up tasks require a passed gate, rather than an output label.
- The HTTP-method probe now validates its narrow TRACE-reflection claim with two independently generated request-header markers and matching request lines. It retains observed response evidence and does not infer credential disclosure or exploitable impact. Static TRACE examples and single reflections do not verify. This adds one read-only probe.
- Detached tool results, evidence reads and nested finding snapshots prevent callers from mutating the runtime evidence behind an existing claim. This is an in-process provenance/validation boundary, not protection against a malicious installed extension or tampering with local checkpoint files.
- Initial five-suite verification passed 48 cases; engine/project/checkpoint integration passed 83; subsequent runtime evidence/report/orchestration cases passed 44. The final four-suite gate run passed 30 cases, plus all five built-artifact gate checks. Runs overlap. TypeScript build exited 0. Changed-source lint has no errors; remaining warnings are existing style warnings after removing new test non-null assertions.
- Browser/authenticated verification, stronger SQLi/XSS/IDOR/SSRF checks, actual verified chains, external-scanner containment and Windows delivery remain open. Other scanner candidates intentionally remain needs-review until corresponding empirical validators exist; this milestone does not complete those capabilities.
