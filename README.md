<div align="center">

<img src="docs/assets/vulnora-wordmark.svg" alt="Vulnora — browser and padlock wordmark" width="560">

**AI-assisted website and API pentesting, built for the terminal.**

[![Status: active development](https://img.shields.io/badge/status-active_development-398AC7?style=flat&labelColor=263341)](#development-status)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-398AC7?style=flat&labelColor=263341)](package.json)
[![Node.js 22.12+](https://img.shields.io/badge/Node.js-22.12%2B-398AC7?style=flat&labelColor=263341)](package.json)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-398AC7?style=flat&labelColor=263341)](LICENSE)

[Features](#features) · [Getting started](#getting-started) · [Architecture](#architecture) · [Development](#development)

</div>

## Overview

Vulnora is a TypeScript CLI for organizing authorized website and API security assessments. It connects reconnaissance and scanning tools with AI-assisted planning, shared evidence, persistent projects and Markdown reports.

The focus is a recoverable workflow: define a target, confirm the scan, inspect live output and return to saved work. AI providers help plan and interpret checks; the execution layer enforces scope and resource budgets.

## Features

- **Website and API assessment** — DNS, HTTP, TLS, content discovery and vulnerability checks, with integrations for tools such as Nmap, Nuclei, ffuf, curl and testssl.sh.
- **Persistent projects** — saved targets, task checkpoints, evidence and complete event journals; recover interrupted work where safe replay is supported.
- **Terminal workspace** — guided project creation, explicit start confirmation, current-stage display, command output, settings and full-output view with `Ctrl+T`.
- **Flexible AI providers** — installed Codex and Claude CLIs reuse their supported login workflows; an installed Ollama model can serve as fallback. Supported deterministic checks remain available without AI.
- **Bounded execution** — shared observations, duplicate-call reuse, scope checks and request budgets; Auto, Stealth and Aggressive modes control load and backoff.
- **Saved reports** — findings, evidence and recommendations remain with the project and export to Markdown; completed projects reopen without starting a new scan.

## Getting started

**Requirements:** Node.js **22.12+**, npm, Git and an ANSI-compatible terminal. External scanner tools must be installed separately; availability depends on the operating system. AI assistance requires a configured provider or an installed Ollama model.

```bash
git clone https://github.com/Havkz/Vulnora.git
cd Vulnora
npm ci
npm run build
npm start
```

Repository access is required while the project is private. This installs the application, not the external scanner binaries. See the [tool installation matrix](docs/INSTALL_MATRIX.md) for dependencies and supported platforms.

### Windows with a dedicated Kali arsenal

The Windows installer deploys a committed release into WSL and installs the `vulnora` command for PowerShell and CMD. It reuses an existing compatible arsenal distribution; a fresh distribution requires a staged, checksum-verified Kali rootfs. Follow the [Windows setup guide](docs/WINDOWS_ARSENAL.md) first.

```powershell
pwsh -NoProfile -File scripts/setup-windows-arsenal.ps1
pwsh -NoProfile -File scripts/install-windows-alias.ps1
vulnora
```

### First assessment

1. Choose **Create New Project**, name it and enter an authorized URL or hostname.
2. Review the target and press Enter at **READY** to begin.
3. Inspect live output; use **Resume Project** to reopen saved work and results.

`Esc` opens the project menu while work continues. Choose **Pause**, or press
`Shift+Esc` in terminals that report modified keys (`Ctrl+P` is also supported),
to stop active work and save progress. A red frame marks the paused state;
**Resume** continues. The live view shows process runtimes and accumulated work
time, excluding pauses; `Ctrl+T` expands command output.

Select providers and scanning behavior in **Settings**. The selected primary provider is tried before the configured Ollama fallback. Startup checks actual inference; no Ollama model is downloaded automatically. The selected local model is held for the session and released on graceful exit.

Configuration and projects live under `~/.vulnora/`; `VULNORA_CONFIG_DIR` selects an alternative directory. Private CLI credential files remain owned by their providers and are neither copied nor modified.

## Architecture

**Terminal UI → Project session → Task orchestration → Tool execution**

The orchestrator connects AI providers with shared evidence. Project sessions persist checkpoints, logs and reports independently of terminal rendering.

- **TypeScript / Node.js** — typed application core, subprocess management and network clients.
- **Terminal rendering** — Chalk, ANSI output and Node.js readline; shared themes, keyboard handling and resize-aware views.
- **Orchestration and persistence** — EventEmitter3, task queues, atomic JSON checkpoints and append-only journals.
- **Provider and tool integrations** — authenticated CLI subprocesses, Ollama HTTP requests and external security binaries.
- **Verification** — Vitest, ESLint and TypeScript checks; GitHub Actions runs Windows and Linux jobs.

## Development

```bash
npm run dev          # Run TypeScript sources
npm run typecheck    # Check types
npm run lint         # Check source quality
npm test             # Run regression tests and preflight checks
npm run build        # Compile to dist/
npm run arsenal:doctor -- --offline --strict
```

Tests include local HTTP/TCP fixtures, checkpoint recovery, scope enforcement, tool-call deduplication, terminal interaction and provider lifecycle behavior. The [CI workflow](.github/workflows/ci.yml) defines the automated checks; external provider access and scanner installation require workstation validation.

## Development status

**Active development.** The CLI, project persistence, provider integration and reporting are implemented. Scanner coverage, timeout handling and terminal interaction continue to be refined; this is not a production-stability claim or a guarantee of complete vulnerability coverage.

Interrupted external processes restart only where safe replay is supported; they do not resume mid-packet. Forced termination may prevent cleanup or model unloading. Use the tool only on systems you own or have explicit permission to assess.

For operational details, see [scan modes](docs/SCAN_MODES.md), [scope and authorization](docs/SCOPE_AND_AUTHORIZATION.md) and [target authentication headers](docs/TARGET_HEADERS.md).

## License and attribution

Licensed under **[AGPL-3.0-or-later](LICENSE)**. Vulnora builds on the existing Tempest codebase. Terminal layout conventions are adapted from VoidAccess; the browser-and-padlock identity and blue palette are original. See [third-party notices](THIRD_PARTY_NOTICES.md).
