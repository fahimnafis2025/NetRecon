<div align="center">

# NetRecon 2.5

### Authorization-first network reconnaissance and attack-surface intelligence

**Discover active assets, understand exposed services, track network drift, and prioritize meaningful security changes over time.**

[Features](#features) · [Quick Start](#quick-start) · [Architecture](#architecture) · [Scan Profiles](#scan-profiles) · [Security Model](#authorization-and-security-model)

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-History-003B57?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-f5a623)
![Status](https://img.shields.io/badge/Status-v2.5.0-5ad67d)

</div>

---

## Overview

Traditional network scans provide a snapshot. They tell you what responded now, but rarely explain what changed, whether a new service appeared, or which exposure deserves attention first.

NetRecon turns authorized network scans into persistent attack-surface intelligence. It combines active-host discovery, service enumeration, device identification, vulnerability context, historical asset observations, drift detection, and deterministic risk scoring in a single local web application.

NetRecon is intentionally **detect-and-report only**. It does not exploit targets, deliver payloads, deauthenticate devices, or perform automated remediation.

> [!IMPORTANT]
> Only scan networks and systems you own or have explicit authorization to assess.

## Why NetRecon

- **Authorization first:** every scan is checked against the operator's allowed CIDR scope.
- **Active devices only:** synthetic `-Pn` results with no supporting evidence are filtered from inventory and the network map.
- **More than a snapshot:** completed scans are persisted in SQLite for first-seen, last-seen, observation, and timeline analysis.
- **Meaningful change detection:** NetRecon identifies new devices, new ports, closed ports, missing devices, disappeared devices, and reappeared devices.
- **Explainable prioritization:** risk scores are deterministic and based on stored exposure, findings, identity confidence, and drift evidence.
- **Local operation:** the application and its historical database remain on the operator's system.

## Screenshots
### Command Center
docs/screenshots/command-center.png

### Asset Explorer
docs/screenshots/asset-explorer.png

### Change Explorer
docs/screenshots/change-explorer.png

### Risk Overview
docs/screenshots/risk-overview.png


## Features

### Reconnaissance and inventory

- Nmap-based active-host discovery and service enumeration
- Optional Naabu-assisted high-speed port discovery
- Optional Nuclei template validation
- MAC address, vendor, hostname, OS, and device-type context
- Per-port service, product, version, banner, purpose, and exposure details
- Scope-gated single-IP probe for deeper inspection
- Current network map containing confirmed active hosts only

### Historical intelligence

- SQLite-backed completed-scan persistence
- Stable asset identity using MAC, identity fingerprint, and IP fallback
- First-seen and last-seen tracking
- Historical observations and previous IP context
- Scan History
- Asset Explorer
- Asset Timeline
- Change Explorer
- Risk Overview

### Drift detection

NetRecon compares compatible completed scans within the same engagement and authorized scope.

| Event | Meaning |
|---|---|
| `new_device` | A confirmed asset was not present in the compatible baseline |
| `new_port` | A new open port/protocol appeared on an existing asset |
| `closed_port` | A previously open port is absent and the current scan had sufficient coverage |
| `possible_disappeared` | An asset is missing from one compatible scan |
| `device_disappeared` | An asset is missing from two consecutive compatible scans |
| `reappeared_device` | A previously missing or disappeared asset is active again |

Closed-port detection is coverage-aware. NetRecon does not claim a port closed when the current scan did not inspect that port.

### Risk prioritization

Risk scores range from 0 to 100 and are mapped to:

| Score | Severity |
|---:|---|
| 90–100 | Critical |
| 70–89 | High |
| 40–69 | Medium |
| 1–39 | Low |
| 0 | Informational |

Newly exposed administrative or legacy services receive deterministic overrides:

| Port | Typical service | New-port severity | Score |
|---:|---|---|---:|
| 445 | SMB | High | 70 |
| 3389 | RDP | High | 70 |
| 23 | Telnet | High | 70 |
| 5900 | VNC | High | 70 |
| 21 | FTP | Medium | 50 |
| 22 | SSH | Low | 25 |

A risk score is triage guidance, not proof that a vulnerability is exploitable.

## User Interface

NetRecon 2.5 uses a single-page application navigation model. Sidebar selections switch views without reloading the page, and active scan/probe state remains mounted while navigating.

Available views:

- Scan
- Inventory
- Ports
- Probe
- Findings
- Assets
- History
- Changes
- Risk
- Network Map

## Architecture

```text
Authorized target and CIDR scope
              |
              v
     Fail-closed Scope Guardrail
              |
              v
   Nmap <---- NetRecon ----> Naabu
              |
              +-----------> Nuclei
              |
              v
 Active-host validation and enrichment
              |
              v
 Current results + SQLite persistence
              |
              v
 Drift engine + deterministic risk engine
              |
              v
 Inventory | History | Timeline | Changes | Risk | Map
```

### Main components

```text
backend/
  main.py                 API, scan orchestration, history routes
  storage.py              SQLite schema, migrations, persistence, queries
  drift.py                Compatibility-aware change detection
  risk.py                 Deterministic event and asset scoring
  scope.py                Authorization and CIDR enforcement
  scanner/
    discovery.py          Nmap parsing and active-host validation
    engines.py            Naabu and Nuclei integration

frontend/
  dashboard.html          Zero-build single-page command center

tests/                    Active-host, persistence, drift, risk, API, and UI tests
docs/
  RUN_GUIDE.md            Detailed operating and validation guide
```

## Scan Profiles

The exact profile names and command previews are displayed in the application.

| Profile | Intended use |
|---|---|
| Ping Sweep | Fast active-device discovery without service enumeration |
| Safe | Balanced service discovery for routine authorized assessment |
| Quick Recon | Faster targeted service discovery |
| Turbo | Naabu-assisted discovery with Nmap enrichment |
| Validate | Naabu, Nmap, and optional Nuclei validation pipeline |
| Thorough | Deeper OS and service enumeration |
| Full | All-port assessment with longer runtime and higher traffic |
| Stealth | Lower-rate SYN-oriented discovery where supported |

Some profiles require elevated privileges. Optional engines are detected at startup and shown in the sidebar.

## Prerequisites

### Kali / Linux

- Python 3
- `python3-venv`
- Nmap
- Naabu and Nuclei for profiles that use those engines
- Root privileges for raw-socket functions, SYN scanning, OS fingerprinting, and reliable Layer 2 identity

Install the core prerequisites on Kali:

```bash
sudo apt update
sudo apt install -y nmap python3-venv
```

### Windows

- Python 3
- Nmap
- Npcap
- Administrator privileges for privileged scan functions

Native scanning is recommended. Docker Desktop networking can obscure Layer 2 visibility and reduce MAC/OS detection accuracy.

## Quick Start

### Kali / Linux

```bash
cd netrecon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x run.sh
sudo ./run.sh
```

Open the local URL printed by the launcher if the browser does not open automatically.

### Windows

```powershell
cd netrecon
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Run the terminal as Administrator when privileged Nmap or Npcap capabilities are required.

## Basic Workflow

1. Enter a target IP or CIDR.
2. Enter the allowed CIDR scope.
3. Provide the authorizer and engagement ID.
4. Choose a scan profile and optional modifiers.
5. Execute the scan.
6. Review current inventory, ports, findings, and map.
7. Repeat a compatible scan to populate changes, risk, and historical views.

The first compatible completed scan becomes the baseline and normally produces no drift events.

## Authorization and Security Model

NetRecon's scope guardrail is fail-closed:

- An authorizer is required.
- An engagement ID is required.
- At least one allowed CIDR is required.
- Every target must fall inside the allowed CIDR list.
- Out-of-scope targets are rejected.
- Historical endpoints require engagement and authorized-scope context.
- Empty allowlists are not treated as unrestricted access.
- Historical queries are isolated by engagement.

Optional signed authorization records can be enforced through the project's configured scope-secret mechanism.

Authorization metadata supports governance but does not itself establish legal permission. The operator remains responsible for obtaining authorization.

## Data Storage

Only successfully completed scans are persisted. Queued, running, failed, cancelled, and interrupted scans do not become historical baselines.

Default database locations:

```text
Privileged Linux launch: /root/.local/share/NetRecon/netrecon.db
Normal Linux launch:     ~/.local/share/NetRecon/netrecon.db
Windows:                 %LOCALAPPDATA%\NetRecon\netrecon.db
```

Override the database path on Linux:

```bash
NETRECON_DB=/var/lib/netrecon/netrecon.db ./run.sh
```

The launcher preserves `NETRECON_DB` through its privileged execution path.

### Backup

```bash
sudo cp /root/.local/share/NetRecon/netrecon.db \
  /root/.local/share/NetRecon/netrecon.db.backup
```

### Reset history

Stop NetRecon first, then remove the relevant database:

```bash
sudo rm /root/.local/share/NetRecon/netrecon.db
```

This resets history and baselines. It does not uninstall NetRecon.

## API

FastAPI provides interactive API documentation while NetRecon is running:

```text
/docs
/redoc
```

Key endpoint groups include:

- Scan and cancellation
- Single-host probe and cancellation
- Profiles and engine availability
- Health and database status
- Read-only historical scans
- Historical assets and timelines
- Stored drift events
- Stored risk summaries

History access remains engagement-scoped and CIDR-authorized.

## Testing

Run the full test suite from the repository root:

```bash
.venv/bin/python -B -m unittest discover -s tests -v
```

The NetRecon 2.5 development cycle includes regression coverage for:

- Active-host filtering
- Nmap and Naabu activity evidence
- Probe compatibility
- SQLite migration and persistence
- Engagement isolation
- Drift transitions
- Coverage-aware port closure
- Risk scoring and overrides
- Historical API authorization
- SPA navigation and historical views

Always validate releases on a real authorized network because host discovery, firewall behavior, privileges, Npcap, and Layer 2 visibility cannot be completely reproduced by unit tests.

## Known Limitations

- Firewalls can suppress discovery probes and cause active devices to be missed.
- MAC/vendor discovery generally requires local Layer 2 visibility and appropriate privileges.
- OS fingerprinting is probabilistic.
- CVE keyword correlation and template matches require analyst verification.
- Device identity falls back to hostname/vendor/device type and then IP when no MAC address is available.
- A sleeping or intermittently connected device may enter the missing-device workflow.
- NetRecon is not a replacement for enterprise vulnerability-management platforms such as Tenable, Qualys, or Rapid7.

## Repository Checklist

Before publishing a release, verify that the repository includes:

- `README.md`
- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `CHANGELOG.md`
- `.gitignore`
- Sanitized screenshots
- No databases, scan exports, tokens, authorization signatures, or private network data

GitHub recommends a README for explaining and navigating a repository, along with supporting files such as a license, contribution guidance, and a code of conduct.

## Roadmap

### Completed in v2.5

- Active-host-only inventory and map
- SQLite persistence and migration support
- First-seen, last-seen, and observation tracking
- Drift detection with disappearance confirmation
- Deterministic risk scoring
- Changes Since Last Scan
- Asset Explorer and Asset Timeline
- Scan History
- Change Explorer
- Risk Overview
- SPA-style sidebar navigation

### Future considerations

- Standalone Windows and Linux release packaging
- Historical report extensions
- Scheduled drift scans and notifications
- Role-based access and multi-tenancy
- Optional ticketing and collaboration integrations

Future work should preserve the authorization-first, detect-and-report-only design.

## Contributing

Contributions are welcome when they preserve NetRecon's safety boundaries and scope enforcement. Read `CONTRIBUTING.md` before opening a pull request.

Do not submit features that add unauthorized scanning, exploitation, credential attacks, payload delivery, deauthentication, or scope bypasses.

## Security

Report suspected vulnerabilities privately according to `SECURITY.md`. Do not include real credentials, authorization signatures, or private network inventories in public issues.

## License

NetRecon is released under the MIT License. See `LICENSE`.

---

<div align="center">

**Built as a practical, authorization-first network visibility and exposure-tracking platform.**

</div>
