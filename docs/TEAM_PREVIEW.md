# T3MP3ST Team Preview

This preview is for prompt engineers, red-teamers, bug bounty operators, cyber researchers, and builders who want to pressure-test T3MP3ST before a broader release.

The useful mental model: T3MP3ST is an evidence-first adversarial AI command center. The CLI combines planning, tool execution, and reporting. It routes a mission into specialist agent lanes, binds tool output to evidence, promotes evidence into findings, retests claims, and only then proposes durable learning.

## Ten-Minute First Run

```bash
npm install
npm run doctor
npm run build
npm start
```

In the CLI, choose **Settings** to configure the provider, then **Start New Operation**. Codex uses the existing `codex login` account. Use **View Status**, **Chat with AI**, and **Generate Report** during an operation, and **Exit** to finish.

An Ollama primary or fallback is preloaded for the interactive session and unloaded on exit. The optional HTTP API remains available through `npm run server`; it does not serve a browser interface.

Expected state on a fresh machine:

- The CLI supports keyless Codex and local Ollama providers.
- LLM calls should fail closed with a clear message.
- The arsenal should distinguish catalog tools, wired adapters, and locally installed tools.
- Missing binaries should be shown as activation work, not hidden as success.

## What Is Real Today

- Interactive CLI and optional Express API server.
- Mission drafts, route previews, mission bundles, and mission gates.
- Resource packs, agent prompt packs, operator runbooks, and forefront pressure lanes.
- Tool adapter catalog with execution modes, evidence kinds, install hints, and receipt gates.
- ScopeGuard approvals for active or networked operations.
- Evidence, hypothesis graph, hunt queue work orders, findings, retests, and accepted-memory proposal flow.
- Watch Loop pulses that surface stale hypotheses, receipt gates, missing disproof, open work orders, retest gaps, and learning proposals.
- Full local smoke scripts for API, arsenal, field drills, exploit-chain simulation, and prompt packs.

## What Is Preview

- Specialist agents are represented by route contracts, prompt packs, runbooks, and orchestration surfaces; production multi-agent execution still needs provider configuration and deeper harness hardening.
- Some Pliny Specials endpoints use synthetic payloads or local-safe demos to validate orchestration shape.
- Catalog-only tools are intentionally modeled but not executable through generic command dispatch.
- Installed tool readiness depends on the local workstation; see `docs/ARSENAL_ACTIVATION_PLAN.md`.

## Demo Missions

Run all local-safe demos:

```bash
npm run field:drill
npm run exploit:smoke
npm run arsenal:smoke
npm run prompt:audit
```

Run one focused field drill:

```bash
npm run field:drill -- --scenario=local-web-api
npm run field:drill -- --scenario=repo-supply-chain
npm run field:drill -- --scenario=ai-agent-boundary
```

Use `examples/demo-missions.json` for plain-language mission seeds that can be copied into the Mission Contract box.

## Feedback We Want

- Where does the UI make the operator feel uncertain?
- Which mission family needs the next real adapter?
- Which prompt pack has the strongest or weakest evidence contract?
- Which hypothesis, work-order, finding, retest, or learning states feel ambiguous?
- Which Watch Loop signals are actionable, noisy, or missing from the always-on hunt?
- Which features look real but should be labeled as preview?
- Which workflow should be one click easier for nontechnical operators?

## Ship Gate For Team Builds

Before pushing a team preview branch, run:

```bash
npm run typecheck
npm test
npm run doctor
npm run arsenal:smoke
```

If the API is not running, `doctor` still checks local files and commands. If the API is running, it also checks health, preflight, arsenal status, and activation metadata.
