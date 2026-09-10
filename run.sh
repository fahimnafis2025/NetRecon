#!/usr/bin/env bash
# NetRecon one-click launcher. First run sets up everything, then serves the app.
# Add --engines to also install Naabu + Nuclei (unlocks Turbo/Validate).
set -e
cd "$(dirname "$0")"
G='\033[0;32m'; Y='\033[1;33m'; N='\033[0m'; say(){ echo -e "${G}[NetRecon]${N} $1"; }; warn(){ echo -e "${Y}[NetRecon]${N} $1"; }
[ -d .venv ] || { say "creating virtual environment…"; python3 -m venv .venv; }
source .venv/bin/activate
say "installing Python dependencies…"; pip install -q --upgrade pip >/dev/null 2>&1 || true; pip install -q -r requirements.txt
if ! command -v nmap >/dev/null 2>&1; then warn "nmap missing — installing…"; sudo apt-get update -qq && sudo apt-get install -y -qq nmap || warn "install nmap manually: sudo apt install nmap"; fi
[ "$1" == "--engines" ] && { bash ./install.sh || warn "engine install had issues"; }
NAABU=$(command -v naabu >/dev/null 2>&1 && echo yes || echo no); NUCLEI=$(command -v nuclei >/dev/null 2>&1 && echo yes || echo no)
say "engines — nmap: yes · naabu: $NAABU · nuclei: $NUCLEI"
[ "$NAABU" == "no" ] && warn "Turbo/Validate locked — run ./run.sh --engines once to unlock."
say "OPEN THIS IN YOUR BROWSER:  http://127.0.0.1:8000   (do NOT open the .html file directly)"
if [ -n "${NETRECON_DB:-}" ]; then
	sudo --preserve-env=NETRECON_DB .venv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
else
	sudo .venv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
fi
