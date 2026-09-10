# NetRecon v2.5 — Run Guide

## Start (one command)
    bash run.sh
Then open **http://127.0.0.1:8000** in your browser.  ⚠️ Do NOT open the .html file directly —
it must be served by the backend or the scan options won't load.

## Dashboard Views
The command center uses single-page navigation. Sidebar selections switch between Scan, Inventory,
Ports, Probe, Findings, Assets, History, Changes, Risk, and Network Map without reloading the page.
Scan and probe state remains mounted while you move between views. Asset Explorer opens Asset Timeline.
The Network Map remains limited to confirmed active hosts from the current scan.

## Unlock Turbo + Validate (Naabu + Nuclei)
    bash run.sh --engines      # one time

## Kali networking
Use your bridged LAN interface (eth1 = 192.168.1.x). Target 192.168.1.0/24.
Never scan 172.x / 10.0.2.x / 192.168.56.x — those are virtual.

## Generate Report
After a scan completes, click "⤓ Generate Report" (top-right). Printable HTML opens in a new tab.

## Persistence
Completed scans are stored in SQLite. Running, failed, cancelled, and queued scans are not persisted.
With `sudo ./run.sh`, data is stored under `/root/.local/share/NetRecon/`. Running the server as a
normal user stores data under `~/.local/share/NetRecon/`. Set `NETRECON_DB` to override the path;
`run.sh` preserves this variable when launching with `sudo`. Phase 2 stores scan metadata, asset
observations, and first/last-seen timestamps; history comparison and history UI are not included yet.

## Back Up and Reset
Back up the database before removing or replacing it:

    sudo cp /root/.local/share/NetRecon/netrecon.db /root/.local/share/NetRecon/netrecon.db.backup

For normal-user execution, replace `/root/.local/share/NetRecon/` with `~/.local/share/NetRecon/`.
To reset persisted data, stop NetRecon and remove the database file:

    sudo rm /root/.local/share/NetRecon/netrecon.db

Existing databases are not moved automatically. Remove the `sudo` prefix for a normal-user database.

## Screenshots
Deployment screenshots may be placed under `docs/screenshots/`. Suggested captures are:

    docs/screenshots/command-center.png
    docs/screenshots/asset-explorer.png
    docs/screenshots/change-explorer.png
    docs/screenshots/risk-overview.png

## Teardown
Ctrl+C. Delete .venv to remove packages. Remove the SQLite database separately if you want to clear
persisted scan data.
