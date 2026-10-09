#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 && $# == 3 ]] || { echo 'Expected root, project archive, config directory and Codex directory' >&2; exit 1; }
archive=$1
windows_config=$2
windows_codex=$3
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y sudo ca-certificates
if ! id tempest >/dev/null 2>&1; then useradd --create-home --shell /bin/bash tempest; fi
printf 'tempest ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/tempest
chmod 440 /etc/sudoers.d/tempest
visudo -cf /etc/sudoers.d/tempest
install -d -o tempest -g tempest -m 700 /home/tempest/app /home/tempest/.t3mp3st /home/tempest/.codex
tar -xf "$archive" -C /home/tempest/app --no-same-owner
chown -R tempest:tempest /home/tempest/app
for config_file in .env config.json; do
  if [[ -f "$windows_config/$config_file" ]]; then
    install -o tempest -g tempest -m 600 "$windows_config/$config_file" "/home/tempest/.t3mp3st/$config_file"
  fi
done
[[ -f "$windows_codex/auth.json" ]] || { echo 'File-based Codex login missing. Authenticate the Linux Codex CLI before setup can finish.' >&2; exit 1; }
install -o tempest -g tempest -m 600 "$windows_codex/auth.json" /home/tempest/.codex/auth.json
printf 'cli_auth_credentials_store = "file"\n' > /home/tempest/.codex/config.toml
chown tempest:tempest /home/tempest/.codex/config.toml
chmod 600 /home/tempest/.codex/config.toml
printf '[user]\ndefault=tempest\n' > /etc/wsl.conf
