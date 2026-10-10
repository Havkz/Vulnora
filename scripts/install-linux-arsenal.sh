#!/usr/bin/env bash
# Run inside the dedicated Kali distribution as the unprivileged Tempest user.
set -euo pipefail
cd "$(dirname "$0")/.."
export DEBIAN_FRONTEND=noninteractive
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
sudo apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=3 update
sudo apt-get install -y --no-install-recommends ca-certificates curl git build-essential pkg-config libpcap-dev \
  golang nodejs npm dirb
node -e 'if(Number(process.versions.node.split(".")[0])<22)throw Error("Node 22 or newer required")'

# Only website/API tools; DNS and service discovery cover their hosts.
packages=(file dnsutils whois nmap subfinder httpx-toolkit naabu katana nuclei ffuf gobuster
  feroxbuster nikto dalfox sqlmap whatweb wafw00f amass dnsx testssl.sh)
available=()
for package in "${packages[@]}"; do
  if apt-cache show "$package" >/dev/null 2>&1; then available+=("$package"); fi
done
sudo apt-get install -y --no-install-recommends "${available[@]}"
mkdir -p "$HOME/.local/bin"
if [[ -x /usr/bin/httpx-toolkit ]]; then ln -sf /usr/bin/httpx-toolkit "$HOME/.local/bin/httpx"; fi
if [[ -f /usr/share/testssl.sh/testssl.sh ]]; then
  ln -sf /usr/share/testssl.sh/testssl.sh "$HOME/.local/bin/testssl.sh"
fi

for recipe in \
  'subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder' \
  'httpx github.com/projectdiscovery/httpx/cmd/httpx' \
  'naabu github.com/projectdiscovery/naabu/v2/cmd/naabu' \
  'katana github.com/projectdiscovery/katana/cmd/katana' \
  'nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei' \
  'dalfox github.com/hahwul/dalfox/v2' \
  'dnsx github.com/projectdiscovery/dnsx/cmd/dnsx' \
  'waybackurls github.com/tomnomnom/waybackurls'; do
  read -r binary module <<< "$recipe"
  if ! command -v "$binary" >/dev/null; then go install "$module@latest"; fi
done
npm install --global --prefix "$HOME/.local" @openai/codex
npm ci
npm run build
nuclei -update-templates
node scripts/arsenal-doctor.mjs --offline --json > "$HOME/arsenal-readiness.json"
node scripts/arsenal-doctor.mjs --offline --strict
touch "$HOME/.tempest-arsenal-ready"
