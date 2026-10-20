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
| Provider routing | Central policy implemented in configuration, TUI and `fallback` CLI; session no longer injects its own ladder. Structured refusal fields, finite retries, audit and actual-model cleanup covered by targeted tests. | Direct `run` overrides and the standalone streaming helper still need integration; verify end-to-end before completion. |
| Model configuration | Existing Codex/Claude CLI model and reasoning selection, Ollama discovery/manual endpoint, lazy lifecycle. | Same options in saved configuration, TUI and direct CLI; installed Codex preferred on fresh setup; actual active model shown. |
| Direct CLI | Existing CLI has setup/status/test/models only. | `run <url>`, resume, scope/exclusions/rate/intensity/provider/fallback/report/config flags; same ProjectSession engine; subprocess integration tests. |
| Scope and load | Existing scope gate, scan policy, budgets and authorization. | Durable per-project scope/exclusions/rate/destructive-action controls enforced on every tool and browser redirect/request. |
| Web surface | Existing HTTP, TLS, headers, content/API discovery and external scanners. | Local fixture discovery of links, JS/API endpoints, forms, parameters, auth; bounded browser support where it adds coverage. |
| Vulnerability tests | Existing website arsenal needs capability-by-capability audit. | Controlled positive and negative fixtures for SQLi, XSS, IDOR, SSRF, authentication, access controls and misconfiguration; inconclusive stays inconclusive. |
| Adaptive planning | Existing task orchestration, evidence store and operator board. | Prioritized hypotheses, dependency-aware concurrent work, useful context, no redundant requests, bounded recovery, traceable decisions. |
| Verification and chains | Existing impact-validation gate and findings. | Captured evidence supports each confirmed finding; controlled retests; chains link supported findings without fabricated impact. |
| Persistence | Atomic project records, checkpoint recovery, event journal already present. | New options and evidence survive stop/restart; interrupted side effects require review; corrupted/incomplete state fails safely. |
| Reports | Existing Markdown reports. | Shared TUI/CLI export, structured findings/evidence/coverage/limitations, escaping and local artifact checks. |
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
