#!/usr/bin/env bash
# Run inside the dedicated Kali distribution as the unprivileged Tempest user.
set -euo pipefail
cd "$(dirname "$0")/.."
export DEBIAN_FRONTEND=noninteractive
export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.foundry/bin:$PATH"
sudo apt-get update
sudo apt-get install -y ca-certificates curl git build-essential pkg-config libpcap-dev libssl-dev \
  libffi-dev python3-dev python3-venv pipx golang nodejs npm unzip jq dirb
node -e 'if(Number(process.versions.node.split(".")[0])<22)throw Error("Node 22 or newer required")'

# Kali packages are preferred; absent packages are collected for an explicit final audit.
packages=(file dnsutils whois nmap subfinder httpx-toolkit naabu katana nuclei ffuf gobuster
  feroxbuster nikto sqlmap semgrep gitleaks trufflehog trivy syft grype osv-scanner checkov
  prowler scoutsuite cloudfox awscli azure-cli garak slither mythril echidna openssl
  john hashcat radamsa afl++ radare2 ghidra binutils gdb checksec apktool jadx apkleaks
  mobsfscan objection frida-tools drozer libimage-exiftool-perl binwalk metasploit-framework hydra
  yara whatweb wafw00f amass dnsx testssl.sh)
available=()
for package in "${packages[@]}"; do
  if apt-cache show "$package" >/dev/null 2>&1; then available+=("$package"); fi
done
sudo apt-get install -y "${available[@]}"
mkdir -p "$HOME/.local/bin"
if [[ -x /usr/bin/httpx-toolkit ]]; then ln -sf /usr/bin/httpx-toolkit "$HOME/.local/bin/httpx"; fi
if [[ -f /usr/share/ghidra/support/analyzeHeadless ]]; then
  ln -sf /usr/share/ghidra/support/analyzeHeadless "$HOME/.local/bin/analyzeHeadless"
fi
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
  'waybackurls github.com/tomnomnom/waybackurls' \
  'gitleaks github.com/zricethezav/gitleaks/v8' \
  'cloudfox github.com/BishopFox/cloudfox' \
  'osv-scanner github.com/google/osv-scanner/v2/cmd/osv-scanner'; do
  read -r binary module <<< "$recipe"
  if ! command -v "$binary" >/dev/null; then go install "$module@latest"; fi
done

# Python tools each get their own environment; Mythril needs an older Python than Kali ships.
if ! command -v uv >/dev/null; then pipx install uv; fi
for recipe in \
  'semgrep semgrep' 'checkov checkov' 'prowler prowler' 'scout scoutsuite' \
  'pmapper principalmapper' 'pacu pacu' 'az azure-cli' 'garak garak' \
  'slither slither-analyzer' 'myth mythril' 'apkleaks apkleaks' 'mobsfscan mobsfscan' \
  'objection objection' 'frida frida-tools' 'drozer drozer' 'wafw00f wafw00f'; do
  read -r binary package <<< "$recipe"
  if ! command -v "$binary" >/dev/null; then
    python_version=3.11
    [[ "$binary" != myth ]] || python_version=3.10
    uv tool install --python "$python_version" "$package"
  fi
done
npm install --global --prefix "$HOME/.local" solhint promptfoo @openai/codex
if ! command -v echidna >/dev/null; then
  release=$(curl --fail --location https://api.github.com/repos/crytic/echidna/releases/latest)
  url=$(jq -r '.assets[] | select(.name | test("x86_64-linux.*tar.gz$")) | .browser_download_url' <<< "$release")
  [[ -n "$url" && "$url" != *$'\n'* ]] || { echo 'No unique Echidna Linux release found' >&2; exit 1; }
  curl --fail --location "$url" -o /tmp/tempest-echidna.tar.gz
  member=$(tar -tzf /tmp/tempest-echidna.tar.gz | grep -E '(^|/)echidna$')
  [[ -n "$member" && "$member" != *$'\n'* ]] || exit 1
  tar -xOf /tmp/tempest-echidna.tar.gz "$member" > "$HOME/.local/bin/echidna"
  chmod 755 "$HOME/.local/bin/echidna"
fi

# Install remaining vendor binaries via their published installers, with failures propagated.
if ! command -v forge >/dev/null || ! command -v cast >/dev/null; then
  curl --fail --location https://foundry.paradigm.xyz -o /tmp/tempest-foundry-install.sh
  bash /tmp/tempest-foundry-install.sh
  "$HOME/.foundry/bin/foundryup"
fi
if ! command -v gcloud >/dev/null; then
  curl --fail --location https://sdk.cloud.google.com -o /tmp/tempest-gcloud-install.sh
  bash /tmp/tempest-gcloud-install.sh --disable-prompts --install-dir="$HOME/.local"
  ln -sf "$HOME/.local/google-cloud-sdk/bin/gcloud" "$HOME/.local/bin/gcloud"
fi
if ! command -v syft >/dev/null; then
  curl --fail --location https://raw.githubusercontent.com/anchore/syft/main/install.sh -o /tmp/tempest-syft-install.sh
  bash /tmp/tempest-syft-install.sh -b "$HOME/.local/bin"
fi
if ! command -v grype >/dev/null; then
  curl --fail --location https://raw.githubusercontent.com/anchore/grype/main/install.sh -o /tmp/tempest-grype-install.sh
  bash /tmp/tempest-grype-install.sh -b "$HOME/.local/bin"
fi
if ! command -v trivy >/dev/null; then
  curl --fail --location https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh -o /tmp/tempest-trivy-install.sh
  bash /tmp/tempest-trivy-install.sh -b "$HOME/.local/bin"
fi
if ! command -v trufflehog >/dev/null; then
  curl --fail --location https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh -o /tmp/tempest-trufflehog-install.sh
  bash /tmp/tempest-trufflehog-install.sh -b "$HOME/.local/bin"
fi
npm ci
npm run build
nuclei -update-templates
node scripts/arsenal-doctor.mjs --offline --json > "$HOME/arsenal-readiness.json"
node scripts/arsenal-doctor.mjs --offline --strict
touch "$HOME/.tempest-arsenal-ready"
