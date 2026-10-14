# Windows CLI with a dedicated Linux arsenal

The `vulnora` launcher reuses `Vulnora-Arsenal` or the existing `Tempest-Arsenal`
distribution with its `tempest` user. These OS identifiers preserve installed tools
and provider authentication. Releases live under `~/.vulnora/releases/<git-revision>`.
Setup installs an archive of the committed repository and records its runtime in
`%USERPROFILE%\.vulnora\sandbox\runtime.json` after successful build and strict checks.
The original application remains available as a rollback boundary.
It opens the terminal CLI. No web UI or API server is started.
Passwordless sudo is granted during installation and removed after the installer succeeds.

Windows must restart after enabling Windows Subsystem for Linux and Virtual Machine Platform.
Run `scripts/setup-windows-arsenal.ps1` to install the runtime. If no existing
distribution is available, setup requires a staged rootfs with verified SHA256SUMS.
Fresh package installation can take substantial time and disk space. A failed install
stops with an error and never publishes the new runtime manifest. It can be
retried by running `vulnora` again.

Setup checks a default route and Kali DNS before package installation. Package-index
download failures abort setup, rather than continuing with incomplete indexes. If mirrored
networking fails with `0x8007054f`, inspect the Windows TCP dynamic port ranges: a widened
range can block WSL's guest port reservation. See [Microsoft's diagnosis](https://github.com/microsoft/WSL/issues/41251).
Back up custom ranges before restoring defaults (`startport=49152 numberofports=16384` for
IPv4/IPv6 TCP), then restart WSL. This repair is not applied automatically by the launcher.
The CLI distribution masks the X11 tmpfiles rule for WSLg's read-only socket mount, avoiding
the [systemd package configuration failure](https://github.com/microsoft/WSL/issues/41488).
APT installs required dependencies without optional desktop recommendations.

The arsenal contains 32 default tools and 23 optional external adapters, all for website/API
testing and supporting DNS, subdomain, TLS and web-server service discovery. Mobile/desktop
app analysis, cloud-account audits, smart contracts, binary analysis, offline hash cracking
and general post-exploitation tools are excluded from registration and model tool contracts.
Kali packages provide common binaries; Go covers the remaining web tools. Nuclei templates
and the directory-discovery wordlist are installed. The installer also installs Node and Codex.
`node scripts/arsenal-doctor.mjs --offline --strict` checks all 23 adapters without an API server.

The launcher starts native Windows Ollama bound to `127.0.0.1:11434` if needed. WSL mirrored
networking lets the Linux application reach that same loopback address. Existing
Windows/WSL networking, kernel and memory settings are preserved by this installer.

Saved provider/model choices remain effective. Codex/Claude reuse authentication
through documented CLI invocation; their credential files are never copied or edited.
Startup validates actual inference and shows failures honestly, permitting supported
fallback, Settings and saved reports. The session holds the selected local model until
graceful exit and unloads that model afterwards. The launcher stops only an Ollama
service it started itself and does not unload an unrelated hardcoded model.

Linux legacy application data is migrated first; Windows Vulnora data fills missing
files only. Destination files and original sources remain intact; migration records
file hashes. After validating the runtime, run `scripts/install-windows-alias.ps1`
to install `vulnora` in PowerShell 7, Windows PowerShell and CMD. Existing `tempest`
profile functions are replaced, and profiles/wrappers are backed up in `.vulnora/backups`.

Regular agents receive installed, relevant, non-equivalent tools. Ollama receives concise
descriptions, required argument markers, defaults and enums. Codex gets longer descriptions
for the same selected tools. Compaction preserves complete tool contracts and the mission
prompt. Fixed coverage recovery executes directly and records the actual tool result.
Reporting uses supplied findings, stored observations and explicit coverage gaps without
advertising new scan tools. Uniform catch-all responses do not count as discovered paths.

This is a separate Linux execution environment, not a hardened hostile-code sandbox.
To check the installer manifest locally, run `npm run build` and `npm run arsenal:test-linux`.
Installed-command and interactive checks are tracked separately in the milestone ledger.
