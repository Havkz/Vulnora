# Scope And Authorization Model

VULNORA is built for authorized security research, owned assets, labs, bug bounty scopes, internal red-team work, and evidence-backed defensive reporting.

The core rule is simple: a mission can be imaginative, aggressive, and adversarial, but the system must preserve scope, evidence, and operator accountability.

## Authority Layers

| Layer | Purpose | Example |
| --- | --- | --- |
| Human intent | The plain-language mission contract | "We own this staging API. Find high-impact risks and produce a fix plan." |
| Scope receipt | Proof that a target and action class are allowed | `command_execution` on `local-host`, or `network_request` for a named range |
| Tool gate | Adapter execution mode | `safe_command`, `receipt_required`, `catalog_only`, `import_only` |
| Evidence ledger | Durable proof before claims | command output, screenshot, report, note, receipt |
| Finding ledger | Claim plus impact and fix | severity, confidence, evidence IDs, acceptance criteria |
| Retest | Validation before promotion | queued, passed, failed, blocked |
| Memory proposal | Human-reviewed durable learning | no silent self-modification |

## Execution Modes

Interactive website projects include the selected domain and its nested
subdomains, including DNS service labels such as `_dmarc`. Other domains and TLDs,
lookalike suffixes and unrelated local addresses remain outside scope. An IP
target authorizes that address, not hostname strings ending in that IP.

## Saved assessment rules

Before starting, `R Rules` on the READY screen edits additional allowed hosts,
excluded hosts, excluded tool IDs and a per-host rate ceiling. The same controls
are available through `run --scope`, `--exclude`, `--exclude-tool` and
`--rate-limit`. Rules persist with the project and its checkpoint. Resume cannot
silently replace them; create a new project for changed authorization boundaries.
Edits use the project lease so another terminal cannot overwrite running work.

- Host rules use bare names or IPs; URL paths, ports, wildcard expressions and
  CIDRs are rejected. An excluded domain includes its subdomains and takes
  precedence over allowance. Host case, trailing dots and equivalent IPv6 forms
  are normalized for comparisons.
- The backend checks tool target parameters, built-in HTTP redirects and DNS
  candidates. Excluded tool IDs are omitted from model definitions and rejected
  before their handler runs, including deterministic backend calls.
- The optional integer rate ceiling is shared across operators' managed HTTP
  requests to a host. Mode/backoff limits still apply. External scanners receive
  their supported rate/delay flags; delay-only clients use one worker under an
  explicit ceiling. Nmap's limit counts probes, not HTTP requests.

These are application controls, not an OS network firewall. The independent
destinations and traffic generated inside external scanner templates still need
broader integration verification. This milestone does not establish containment
of arbitrary third-party templates or custom executables. Path-level exclusions
and independent enforcement of every third-party template action remain outstanding integration work.

## Excluded risk classes

Use `--exclude-risk dangerous --exclude-risk credential`, the run-profile
`excludeRisk` array, or READY → `R Rules` → `Excluded risk classes`. These rules
are stored with the project/checkpoint and exported in its report. Missing or
empty exclusions preserve existing behavior; changing them requires a new project.

Classes are `local_read`, `passive`, `active`, `intrusive`, `credential`, and
`dangerous`. Tools use their declared/catalog risk; built-in XSS/SQLi/LFI/SSTI
checks are intrusive and password spraying is credential work. Untyped extensions
are conservatively dangerous. Matching tools disappear from model definitions;
direct and backend calls are rejected before handlers run, even if pre-approved.

For managed HTTP and curl calls, methods other than GET/HEAD/OPTIONS/TRACE and
nonempty request bodies count as dangerous. Excluding `dangerous` blocks those
calls, including requests made inside built-in probes. Excluding `active` also
blocks managed bodyless HTTP. These are conservative action classifications,
not a guarantee that a GET endpoint or an allowed third-party template is harmless.
External scanner subprocesses still require template-level review/containment;
use exact tool exclusions when their internal requests are not acceptable.

## Tool execution modes

- `safe_command`: local-read or lab-safe command, still logged and evidence-oriented.
- `receipt_required`: active, networked, credential-adjacent, or otherwise risky command.
- `catalog_only`: known capability that should not run through generic command execution.
- `import_only`: evidence can be imported, but collection stays outside generic execution.

## Non-Negotiables

- No third-party target without explicit scope.
- No production writes without a named approval.
- No copying raw secrets, tokens, credentials, private keys, or recovered passwords into evidence.
- No generic execution surface for broad exploitation or credential tooling.
- Findings need evidence and retests before they become confident claims.
- Memory needs operator acceptance before it becomes durable.

## Reviewer Checklist

- Can I tell what target is in scope?
- Can I tell which action class is approved?
- Can I tell which tool output supports each claim?
- Can I retest the claim?
- Can a nontechnical stakeholder understand the risk and next action?
- Can a technical stakeholder reproduce the evidence?
