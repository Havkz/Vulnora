# Windows CLI with a dedicated Linux arsenal

The local `tempest` launcher uses the WSL 2 distribution `Tempest-Arsenal`. Its disk and
verified Kali rootfs live in `%USERPROFILE%\.t3mp3st\sandbox`. The application runs as
the Linux user `tempest` in `/home/tempest/app`, from an archive of the committed repository.
It opens the terminal CLI. No web UI or API server is started.
Passwordless sudo is granted during installation and removed after the installer succeeds.

Windows must restart after enabling Windows Subsystem for Linux and Virtual Machine Platform.
The first `tempest` invocation then imports the staged rootfs and installs the arsenal using
`scripts/setup-windows-arsenal.ps1`. Package installation can take substantial time and disk
space. A failed install stops with an error and never writes the readiness marker. It can be
retried by running `tempest` again.

Setup checks a default route and Kali DNS before package installation. Package-index
download failures abort setup, rather than continuing with incomplete indexes. If mirrored
networking fails with `0x8007054f`, inspect the Windows TCP dynamic port ranges: a widened
range can block WSL's guest port reservation. See [Microsoft's diagnosis](https://github.com/microsoft/WSL/issues/41251).
Back up custom ranges before restoring defaults (`startport=49152 numberofports=16384` for
IPv4/IPv6 TCP), then restart WSL. This repair is not applied automatically by the launcher.

The arsenal contains 32 default tools and 23 optional external adapters, all for website/API
testing and supporting DNS, subdomain, TLS and web-server service discovery. Mobile/desktop
app analysis, cloud-account audits, smart contracts, binary analysis, offline hash cracking
and general post-exploitation tools are excluded from registration and model tool contracts.
Kali packages provide common binaries; Go covers the remaining web tools. Nuclei templates
and the directory-discovery wordlist are installed. The installer also installs Node and Codex.
`node scripts/arsenal-doctor.mjs --offline --strict` checks all 23 adapters without an API server.

The launcher starts native Windows Ollama bound to `127.0.0.1:11434` if needed. WSL mirrored
networking lets the Linux application reach that same loopback address. Existing custom
kernel settings are preserved; the previous `.wslconfig` is backed up in the sandbox folder.
The Linux VM is limited to 4 GB RAM plus 4 GB swap to leave memory for the Windows model.

Codex remains the primary provider. The existing file-based Codex login is copied with
private Linux file permissions; Windows hooks and global CLI configuration are not copied.
The first interactive launch checks a harmless Base64 harness call with Codex, then injects
a missing Codex executable to verify Ollama fallback with the same tool. This check must pass
before the provider-verification marker is written. The interactive session loads the local
model, holds it until exit, and unloads it afterwards. The launcher stops only an Ollama
service it started itself.

Regular agents receive installed, relevant, non-equivalent tools. Ollama receives concise
descriptions, required argument markers, defaults and enums. Codex gets longer descriptions
for the same selected tools. Compaction preserves complete tool contracts and the mission
prompt. Fixed coverage recovery executes directly and records the actual tool result.
Reporting uses supplied findings, stored observations and explicit coverage gaps without
advertising new scan tools. Uniform catch-all responses do not count as discovered paths.

This is a separate Linux execution environment, not a hardened hostile-code sandbox.
To check the installer manifest locally, run `npm run build` and `npm run arsenal:test-linux`.
The first installation and interactive Linux behavior must be verified after the reboot.
