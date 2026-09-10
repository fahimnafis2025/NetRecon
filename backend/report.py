"""NetRecon - Report generator. Self-contained HTML (printable to PDF). No external deps."""
from __future__ import annotations
import html
from datetime import datetime, timezone


def _esc(s):
    return html.escape(str(s if s is not None else ""))


def _rank(sev):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "NONE": 5}.get(sev, 6)


def build_report(scan: dict) -> str:
    hosts = scan.get("hosts", [])
    profile = scan.get("profile", "")
    engagement = scan.get("engagement_id", "")
    targets = ", ".join(scan.get("targets", []))
    started = scan.get("started_at") or scan.get("created_at") or ""
    finished = scan.get("finished_at") or ""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total = len(hosts)
    identified = sum(1 for h in hosts if h.get("device_type") not in (None, "", "unknown"))
    risk_flags = nuclei_hits = 0
    cve_rows, risk_rows, nuc_rows = [], [], []
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for h in hosts:
        ip = h.get("ip", "")
        name = h.get("hostname") or h.get("device_type") or ip
        for r in h.get("risks", []):
            risk_flags += 1
            risk_rows.append((ip, name, r.get("port"), r.get("note"), r.get("level", "info")))
        for n in h.get("nuclei", []):
            nuclei_hits += 1
            s = n.get("severity", "NONE")
            if s in sev:
                sev[s] += 1
            nuc_rows.append((ip, s, n.get("template_id", ""), n.get("matched_at", "")))
        for f in h.get("findings", []):
            s = f.get("severity", "NONE")
            if s in sev:
                sev[s] += 1
            cve_rows.append((ip, f.get("port"), f.get("product", ""), f.get("version", ""),
                             f.get("cve_id", ""), f.get("cvss", ""), s, f.get("remediation", "")))

    risk_rows.sort(key=lambda r: {"high": 0, "medium": 1, "info": 2}.get(r[4], 3))
    nuc_rows.sort(key=lambda r: _rank(r[1]))
    cve_rows.sort(key=lambda r: _rank(r[6]))
    high_crit = sev["CRITICAL"] + sev["HIGH"] + sum(1 for r in risk_rows if r[4] == "high")
    posture = "GOOD"
    if high_crit >= 5:
        posture = "NEEDS ATTENTION"
    elif high_crit >= 1:
        posture = "FAIR"

    def rows(lst, cols):
        return "".join(lst) if lst else '<tr><td colspan="%d" class="muted">None found.</td></tr>' % cols

    inv = ""
    for h in hosts:
        ports = ", ".join(str(s.get("port")) for s in sorted(h.get("services", []), key=lambda s: s.get("port", 0)))
        rk = " ".join('<span class="tag t-%s">%s</span>' % (_esc(r.get("level")), _esc(r.get("note"))) for r in h.get("risks", [])) or '<span class="muted">—</span>'
        inv += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='mono'>%s</td><td>%s</td></tr>" % (
            _esc(h.get("ip")), _esc(h.get("hostname") or "—"), _esc(h.get("device_type")), _esc(h.get("confidence")),
            _esc(h.get("friendly_vendor") or h.get("vendor") or "—"), _esc(ports or "—"), rk)

    riskt = rows(["<tr><td>%s</td><td>%s</td><td class='mono'>%s</td><td>%s</td><td><span class='tag t-%s'>%s</span></td></tr>" % (
        _esc(a), _esc(b), _esc(c), _esc(d), _esc(e), _esc(e.upper())) for a, b, c, d, e in risk_rows], 5)
    nuct = rows(["<tr><td>%s</td><td><span class='sev s-%s'>%s</span></td><td class='mono'>%s</td><td class='mono'>%s</td></tr>" % (
        _esc(a), _esc(b), _esc(b), _esc(c), _esc(d)) for a, b, c, d in nuc_rows], 4)
    cvet = rows(["<tr><td>%s</td><td class='mono'>%s</td><td>%s %s</td><td class='mono'>%s</td><td>%s</td><td><span class='sev s-%s'>%s</span></td><td>%s</td></tr>" % (
        _esc(a), _esc(b), _esc(c), _esc(d), _esc(e), _esc(f), _esc(g), _esc(g), _esc(h2)) for a, b, c, d, e, f, g, h2 in cve_rows], 8)

    return """<!DOCTYPE html><html><head><meta charset="utf-8"><title>NetRecon Report - %(eng)s</title>
<style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono&display=swap');
*{box-sizing:border-box}body{font-family:Inter,Arial,sans-serif;color:#1a2230;margin:0;background:#f4f6fa;font-size:13px;line-height:1.5}
.page{max-width:900px;margin:0 auto;padding:40px;background:#fff}
h1{font-size:24px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid #f59e0b;color:#7a4a08}
.sub{color:#5b6b7b;font-size:12.5px}.mono{font-family:'JetBrains Mono',monospace;font-size:11.5px}
.head{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #f59e0b;padding-bottom:16px}
.logo{font-size:20px;font-weight:700;color:#f59e0b}.meta{font-size:12px;color:#5b6b7b;text-align:right}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:18px 0}
.card{border:1px solid #e2e8f0;border-radius:10px;padding:14px;text-align:center;background:#fbfcfe}
.card .n{font-size:26px;font-weight:700;font-family:'JetBrains Mono',monospace}.card .l{font-size:10.5px;color:#5b6b7b;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
.posture{display:inline-block;padding:4px 12px;border-radius:6px;font-weight:700;font-size:12px}
.p-GOOD{background:#dcfce7;color:#166534}.p-FAIR{background:#fef9c3;color:#854d0e}.p-NEEDS{background:#fee2e2;color:#991b1b}
table{width:100%%;border-collapse:collapse;margin-top:8px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #e8edf3;vertical-align:top;font-size:12px}
th{background:#f1f5f9;color:#475569;font-size:10.5px;text-transform:uppercase}
.tag{display:inline-block;font-size:10px;padding:1px 6px;border-radius:4px;margin:1px}
.t-high{background:#fee2e2;color:#991b1b}.t-medium{background:#fef9c3;color:#854d0e}.t-info{background:#e0f2fe;color:#075985}
.sev{font-weight:600;font-size:11px}.s-CRITICAL{color:#dc2626}.s-HIGH{color:#ea580c}.s-MEDIUM{color:#ca8a04}.s-LOW{color:#16a34a}.s-INFO{color:#0891b2}
.muted{color:#94a3b8}.note{background:#f8fafc;border-left:3px solid #f59e0b;padding:10px 14px;margin:12px 0;font-size:12px;color:#475569}
.foot{margin-top:32px;padding-top:14px;border-top:1px solid #e2e8f0;font-size:11px;color:#94a3b8;text-align:center}
@media print{body{background:#fff}.page{padding:20px}}</style></head><body><div class="page">
<div class="head"><div><div class="logo">&#9678; NetRecon</div><h1>Attack-Surface Assessment</h1>
<div class="sub">Engagement: <b>%(eng)s</b> &nbsp;·&nbsp; Scope: <span class="mono">%(targets)s</span></div></div>
<div class="meta">Profile: <b>%(profile)s</b><br>Started: %(started)s<br>Finished: %(finished)s<br>Generated: %(generated)s</div></div>
<h2>Executive Summary</h2>
<p>This assessment discovered <b>%(total)d</b> live host(s) on the authorized scope, of which <b>%(identified)d</b>
were identified by type. NetRecon flagged <b>%(risk_flags)d</b> risky exposed service(s) and <b>%(nuclei_hits)d</b>
template-validated finding(s). Overall posture: <span class="posture p-%(pkey)s">%(posture)s</span>.</p>
<div class="cards">
<div class="card"><div class="n">%(total)d</div><div class="l">Devices</div></div>
<div class="card"><div class="n">%(identified)d</div><div class="l">Identified</div></div>
<div class="card"><div class="n" style="color:#ea580c">%(risk_flags)d</div><div class="l">Risk Flags</div></div>
<div class="card"><div class="n">%(nuclei_hits)d</div><div class="l">Nuclei Hits</div></div>
<div class="card"><div class="n" style="color:#dc2626">%(high_crit)d</div><div class="l">High / Crit</div></div></div>
<div class="note"><b>Method:</b> Authorization-gated discovery (nmap%(pipe)s) with deterministic device
fingerprinting and exposure analysis. Detect-and-report only — no exploitation was performed. CVE matches are
NVD keyword-based and should be manually validated.</div>
<h2>Exposed Service Risks</h2><table><thead><tr><th>Host</th><th>Name</th><th>Port</th><th>Exposure</th><th>Level</th></tr></thead><tbody>%(riskt)s</tbody></table>
<h2>Validated Findings (Nuclei)</h2><table><thead><tr><th>Host</th><th>Severity</th><th>Template</th><th>Matched</th></tr></thead><tbody>%(nuct)s</tbody></table>
<h2>CVE Findings (NVD keyword)</h2><table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>CVE</th><th>CVSS</th><th>Sev</th><th>Remediation</th></tr></thead><tbody>%(cvet)s</tbody></table>
<h2>Device Inventory</h2><table><thead><tr><th>IP</th><th>Hostname</th><th>Device</th><th>Conf.</th><th>Vendor</th><th>Ports</th><th>Risk</th></tr></thead><tbody>%(inv)s</tbody></table>
<div class="foot">NetRecon &middot; authorization-first attack-surface scanner &middot; report generated %(generated)s<br>
For internal self-audit use. Findings require validation before remediation action.</div>
</div></body></html>""" % {
        "eng": _esc(engagement or "NetRecon Scan"), "targets": _esc(targets or "—"), "profile": _esc(profile),
        "started": _esc(started), "finished": _esc(finished), "generated": _esc(generated),
        "total": total, "identified": identified, "risk_flags": risk_flags, "nuclei_hits": nuclei_hits,
        "high_crit": high_crit, "posture": posture, "pkey": "NEEDS" if posture == "NEEDS ATTENTION" else posture,
        "pipe": " + Naabu + Nuclei" if profile in ("turbo", "validate") else "",
        "riskt": riskt, "nuct": nuct, "cvet": cvet, "inv": inv or '<tr><td colspan="7" class="muted">No hosts.</td></tr>',
    }
