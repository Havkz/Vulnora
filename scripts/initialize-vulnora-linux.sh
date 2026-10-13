#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 && $# == 2 ]] || { echo 'Expected root, project archive and config directory' >&2; exit 1; }
archive=$1
windows_config=$2
if ! ip route show default | grep -q '^default'; then
  echo 'Vulnora WSL network unavailable: no default route. Check WSL mirrored networking before installing packages.' >&2
  exit 1
fi
if ! timeout 20 getent ahosts http.kali.org >/dev/null; then
  echo 'Vulnora WSL DNS unavailable: cannot resolve http.kali.org. Repair WSL networking before installing packages.' >&2
  exit 1
fi
# WSLg's read-only sockets must not be chmodded by systemd package configuration.
if mountpoint -q /tmp/.X11-unix; then
  install -d /etc/tmpfiles.d
  ln -sf /dev/null /etc/tmpfiles.d/x11.conf
fi
apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=3 update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sudo ca-certificates
if ! id vulnora >/dev/null 2>&1; then useradd --create-home --shell /bin/bash vulnora; fi
printf 'vulnora ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/vulnora
chmod 440 /etc/sudoers.d/vulnora
visudo -cf /etc/sudoers.d/vulnora
install -d -o vulnora -g vulnora -m 700 /home/vulnora/app /home/vulnora/.vulnora
tar -xf "$archive" -C /home/vulnora/app --no-same-owner
chown -R vulnora:vulnora /home/vulnora/app
for config_file in .env config.json; do
  if [[ -f "$windows_config/$config_file" ]]; then
    install -o vulnora -g vulnora -m 600 "$windows_config/$config_file" "/home/vulnora/.vulnora/$config_file"
  fi
done
printf '[user]\ndefault=vulnora\n' > /etc/wsl.conf
