#!/usr/bin/env bash
# install-tools.sh — install the website/API arsenal on a Homebrew workstation.
# For Windows/Kali use scripts/setup-windows-arsenal.ps1 and install-linux-arsenal.sh.
# Usage: --web (default), --all, --min, --recon, --web-only, --list
# Not run with -e: a single failed install must not abort the rest.
set -uo pipefail

GROUP="default"; LIST=""
for a in "$@"; do case "$a" in
  --web) GROUP="web";; --min) GROUP="min";; --all) GROUP="all";;
  --recon) GROUP="recon";; --web-only) GROUP="webonly";;
  --list|-n) LIST=1;;
  -h|--help) sed -n '2,5p' "$0"; exit 0;;
  *) echo "unknown flag: $a (try --help)"; exit 2;;
esac; done

have(){ command -v "$1" >/dev/null 2>&1; }

# need <binary> <installer cmd...>
need(){
  local bin="$1"; shift
  if have "$bin"; then echo "  ✓ $bin"; return 0; fi
  if [ -n "$LIST" ]; then echo "  + $bin  ←  $*"; return 0; fi
  echo "  → $bin : $*"
  if "$@"; then echo "    ok"; else echo "    FAIL ($bin) — see output above / docs/INSTALL_MATRIX.md"; fi
}

# Prereq managers (warn, don't fail — a tool that needs a missing manager just FAILs its line).
if ! have brew && [ -z "$LIST" ]; then echo " Homebrew not found — brew-based tools will FAIL. https://brew.sh"; fi
PIPX=pipx; have pipx || PIPX="python3 -m pipx"   # fall back if pipx isn't a shim

recon(){    echo "──  recon/osint ──"
  need file        brew install file
  need curl        brew install curl
  need dig         brew install bind
  need host        brew install bind
  need whois       brew install whois
  need dnsx        brew install projectdiscovery/tap/dnsx
  need amass       brew install amass
  need waybackurls go install github.com/tomnomnom/waybackurls@latest
  need nmap        brew install nmap
  need httpx       brew install projectdiscovery/tap/httpx
  need naabu       brew install projectdiscovery/tap/naabu
  need katana      brew install projectdiscovery/tap/katana
  need subfinder   brew install projectdiscovery/tap/subfinder
  need nuclei      brew install nuclei
}
web(){      echo "──  web exploitation ──"
  need ffuf        brew install ffuf
  need gobuster    brew install gobuster
  need feroxbuster brew install feroxbuster
  need nikto       brew install nikto
  need dalfox      brew install dalfox
  need sqlmap      brew install sqlmap
  need whatweb     brew install whatweb
  need wafw00f     $PIPX install wafw00f
  need testssl.sh  brew install testssl
}
echo "VULNORA arsenal installer — group: $GROUP${LIST:+ (dry-run)}"
case "$GROUP" in
  default)  recon; web;;
  web)      recon; web;;
  webonly)  web;;
  min)      recon; web;;
  recon)    recon;;
  all)      recon; web;;
esac

echo
echo "Done. Verify readiness with: npm run arsenal:doctor -- --offline --strict"
