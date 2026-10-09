# T3MP3ST Install Matrix

Use this as the team-facing view of what a workstation needs. The CLI and API remain useful without every binary installed, but local command readiness improves as these tools appear on `PATH`.

The runtime requires **Node.js 22.12.0 or newer**, npm and Git. CI checks Windows and Linux. Windows resolves native binaries and command shims via `PATH` and `PATHEXT`; POSIX-only tools remain optional and require a compatible installation.

Windows local agents use native executables or standard npm Node shims. npm shims launch their Node entrypoint directly, keeping prompts out of the command shell. Other `.cmd`/`.bat` wrappers are rejected; use a native executable for those installations.

To isolate app settings, set `T3MP3ST_CONFIG_DIR` to an absolute directory. It holds `config.json` and the app's `.env`; home-directory env files are ignored while this override is set. Tests always use a temporary directory.

| Lane | Tools | macOS | Linux Notes | Execution |
| --- | --- | --- | --- | --- |
| Core evidence | `file`, `curl`, `dig`, `host`, `whois` | Usually present or `brew install bind openssl@3` | Usually package-manager available | Mixed local and receipt-gated |
| Web/API recon | `nmap`, `subfinder`, `httpx`, `naabu`, `katana`, `nuclei` | Homebrew plus ProjectDiscovery tap | Prefer distro packages or upstream release binaries | Receipt-gated |
| Web/API pressure | `ffuf`, `gobuster`, `feroxbuster`, `nikto`, `dalfox`, `sqlmap` | Homebrew | Distro packages, Go installs, or upstream releases | Receipt-gated |
| Web/TLS fingerprinting | `whatweb`, `wafw00f`, `testssl.sh` | Homebrew or pipx | Kali packages | Receipt-gated |
| DNS/archive discovery | `amass`, `dnsx`, `waybackurls` | Homebrew or Go | Kali packages or Go | Receipt-gated |

## macOS Homebrew Repair

If Homebrew is owned by a different local user, installs may fail with `Cellar is not writable` or tap permission errors. Repair the prefix before installing tools:

```bash
sudo chown -R "$(whoami)":admin /opt/homebrew
brew doctor
```

## Website/API installation

On Windows, the `tempest` launcher provisions a dedicated Kali distribution with all 23
external website/API adapters. See [Windows CLI setup](WINDOWS_ARSENAL.md).
Mobile/desktop apps, cloud-account audits, smart contracts, binary analysis and general
post-exploitation are excluded from the active arsenal and installers.

On a Homebrew workstation, `scripts/install-tools.sh --web` installs the corresponding web
tools. `npm run arsenal:doctor -- --offline --strict` verifies the binaries on PATH.
