#!/usr/bin/env bash
# Installs Naabu + Nuclei. Unlocks Turbo & Validate profiles.
set -e
G='\033[0;32m'; N='\033[0m'; say(){ echo -e "${G}[engines]${N} $1"; }
if command -v apt-get >/dev/null 2>&1 && apt-cache show naabu >/dev/null 2>&1; then
  say "installing via apt…"; sudo apt-get update -qq
  sudo apt-get install -y -qq naabu nuclei && { say "done via apt."; nuclei -update-templates -silent 2>/dev/null || true; exit 0; }
fi
say "installing via Go (may take a few minutes)…"
command -v go >/dev/null 2>&1 || { sudo apt-get update -qq && sudo apt-get install -y -qq golang-go libpcap-dev build-essential; }
export CGO_ENABLED=1
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
grep -q 'go/bin' ~/.zshrc 2>/dev/null || echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
grep -q 'go/bin' ~/.bashrc 2>/dev/null || echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
export PATH=$PATH:$HOME/go/bin
sudo ln -sf "$HOME/go/bin/naabu" /usr/local/bin/naabu 2>/dev/null || true
sudo ln -sf "$HOME/go/bin/nuclei" /usr/local/bin/nuclei 2>/dev/null || true
nuclei -update-templates -silent 2>/dev/null || true
say "done. verify: naabu -version ; nuclei -version"
