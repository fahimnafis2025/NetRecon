"""NetRecon FastAPI - v2.5 command center. Serves dashboard + full API on one port."""
from __future__ import annotations
import logging
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from backend.scope import Authorization, OutOfScopeError, enforce
from backend.scanner.discovery import (
    DEFAULT_PROFILE, PROFILES, MODIFIERS,
    profile_catalog, modifier_catalog, run_scan, host_to_dict, probe_host,
)
from backend.scanner.engines import engine_status
from backend.vuln.cve_lookup import lookup, finding_to_dict
from backend.report import build_report
from backend.storage import Storage

ROOT = Path(__file__).resolve().parent.parent
_LOGGER = logging.getLogger(__name__)
app = FastAPI(title="NetRecon", version="2.5.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

_SCANS: dict = {}
_PROBES: dict = {}
_PROCS: dict = {}
STORAGE = Storage()


def _now():
    return datetime.now(timezone.utc)


def _iso(d):
    return d.isoformat() if d else None


def _elapsed(j):
    s = j.get("_start")
    return round(((j.get("_end") or _now()) - s).total_seconds(), 1) if s else 0.0


def _pub(j):
    o = {k: v for k, v in j.items() if not k.startswith("_")}
    o["elapsed_seconds"] = _elapsed(j)
    o["log"] = list(j.get("_log", []))
    return o


def _kill(jid):
    p = _PROCS.get(jid)
    if p and p.poll() is None:
        try:
            p.terminate()
            try:
                p.wait(timeout=3)
            except Exception:
                p.kill()
            return True
        except Exception:
            return False
    return False


class ScanRequest(BaseModel):
    targets: List[str]
    profile: str = DEFAULT_PROFILE
    modifiers: List[str] = Field(default_factory=list)
    authorized_by: str
    engagement_id: str
    allowed_cidrs: List[str] = Field(default_factory=list)
    note: str = ""
    extra_args: Optional[List[str]] = None


class ProbeRequest(BaseModel):
    ip: str
    depth: str = "standard"
    skip_ping: bool = True
    authorized_by: str
    engagement_id: str
    allowed_cidrs: List[str] = Field(default_factory=list)


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(ROOT / "frontend" / "dashboard.html")


@app.get("/health")
def health():
    return {"status": "ok", "version": app.version, "time": _iso(_now()),
            "database": STORAGE.database_info()}


@app.get("/engines")
def engines():
    return engine_status()


@app.get("/profiles")
def profiles():
    return {"default": DEFAULT_PROFILE, "profiles": profile_catalog(),
            "modifiers": modifier_catalog(), "engines": engine_status()}


def _history_scope(engagement_id: str, authorized_by: str, allowed_cidrs: str):
    auth = Authorization(authorized_by, engagement_id, [item.strip() for item in allowed_cidrs.split(",") if item.strip()])
    try:
        enforce([], auth)
    except OutOfScopeError:
        if not auth.networks():
            raise HTTPException(403, f"Refused: empty allowlist for '{engagement_id}'.")
    return auth


def _history_result_scope(rows, auth):
    visible = []
    for row in rows:
        ip = row.get("last_ip") or row.get("ip")
        if ip:
            try:
                enforce([ip], auth)
            except OutOfScopeError:
                continue
        visible.append(row)
    return visible


@app.get("/history/scans")
def history_scans(engagement_id: str, authorized_by: str, allowed_cidrs: str,
                  limit: int = 100, offset: int = 0):
    auth = _history_scope(engagement_id, authorized_by, allowed_cidrs)
    return {"scans": _history_result_scope(STORAGE.list_history_scans(engagement_id, limit, offset), auth)}


@app.get("/history/assets")
def history_assets(engagement_id: str, authorized_by: str, allowed_cidrs: str,
                   status: Optional[str] = None, risk_severity: Optional[str] = None,
                   limit: int = 100, offset: int = 0):
    auth = _history_scope(engagement_id, authorized_by, allowed_cidrs)
    assets = STORAGE.list_history_assets(engagement_id, status, risk_severity, limit, offset)
    return {"assets": _history_result_scope(assets, auth)}


@app.get("/history/assets/{asset_id}/timeline")
def history_asset_timeline(asset_id: int, engagement_id: str, authorized_by: str, allowed_cidrs: str):
    auth = _history_scope(engagement_id, authorized_by, allowed_cidrs)
    timeline = STORAGE.asset_timeline(engagement_id, asset_id)
    return {"timeline": _history_result_scope(timeline, auth)}


@app.get("/history/changes")
def history_changes(engagement_id: str, authorized_by: str, allowed_cidrs: str,
                    event_type: Optional[str] = None, severity: Optional[str] = None,
                    limit: int = 100, offset: int = 0):
    auth = _history_scope(engagement_id, authorized_by, allowed_cidrs)
    changes = STORAGE.list_history_changes(engagement_id, event_type, severity, limit, offset)
    return {"changes": _history_result_scope(changes, auth)}


@app.get("/history/risk")
def history_risk(engagement_id: str, authorized_by: str, allowed_cidrs: str):
    auth = _history_scope(engagement_id, authorized_by, allowed_cidrs)
    overview = STORAGE.history_risk_overview(engagement_id)
    overview["top_assets"] = _history_result_scope(overview["top_assets"], auth)
    overview["recent_changes"] = _history_result_scope(overview["recent_changes"], auth)
    return overview


@app.post("/scans")
def create_scan(req: ScanRequest):
    auth = Authorization(req.authorized_by, req.engagement_id, req.allowed_cidrs, note=req.note)
    try:
        validated = enforce(req.targets, auth)
    except OutOfScopeError as e:
        raise HTTPException(403, str(e))
    if req.profile not in PROFILES:
        raise HTTPException(400, f"Unknown profile '{req.profile}'.")
    for m in req.modifiers:
        if m not in MODIFIERS:
            raise HTTPException(400, f"Unknown modifier '{m}'.")
    sid = uuid.uuid4().hex[:12]
    _SCANS[sid] = {
        "scan_id": sid, "status": "queued", "profile": req.profile, "targets": validated,
        "engagement_id": req.engagement_id, "created_at": _iso(_now()), "started_at": None,
        "finished_at": None, "privileged": None,
        "progress": {"percent": 0.0, "phase": "queued", "eta": ""},
        "hosts": [], "error": None, "_start": None, "_end": None, "_log": deque(maxlen=400),
        "_authorized_by": req.authorized_by, "_authorization_note": req.note,
        "_allowed_cidrs": list(req.allowed_cidrs), "_modifiers": list(req.modifiers),
    }
    threading.Thread(target=_run, args=(sid, validated, req.profile, req.modifiers, req.extra_args), daemon=True).start()
    return {"scan_id": sid, "status": "queued", "targets": validated}


@app.get("/scans/{sid}")
def get_scan(sid):
    s = _SCANS.get(sid)
    if not s:
        raise HTTPException(404, "scan not found")
    return _pub(s)


@app.post("/scans/{sid}/cancel")
def cancel_scan(sid):
    s = _SCANS.get(sid)
    if not s:
        raise HTTPException(404, "scan not found")
    if s["status"] in ("complete", "error", "cancelled"):
        return _pub(s)
    s["_cancel"] = True
    _kill(sid)
    s["status"] = "cancelled"
    s["_end"] = _now()
    s["finished_at"] = _iso(s["_end"])
    s["progress"] = {"percent": s["progress"].get("percent", 0.0), "phase": "cancelled", "eta": ""}
    s["_log"].append("scan cancelled by user.")
    return _pub(s)


@app.get("/scans/{sid}/report", response_class=HTMLResponse)
def scan_report(sid):
    s = _SCANS.get(sid)
    if not s:
        raise HTTPException(404, "scan not found")
    return HTMLResponse(build_report(_pub(s)))


def _run(sid, targets, profile, modifiers, extra_args):
    s = _SCANS[sid]
    s["status"] = "scanning"
    s["_start"] = _now()
    s["started_at"] = _iso(s["_start"])

    def prog(p, ph, e):
        s["progress"] = {"percent": round(p, 1), "phase": ph, "eta": e}

    def log(l):
        s["_log"].append(f"{datetime.now().strftime('%H:%M:%S')}  {l}")

    def reg(p):
        _PROCS[sid] = p

    try:
        hosts, priv = run_scan(targets, profile=profile, modifiers=modifiers, extra_args=extra_args,
                               progress_cb=prog, log_cb=log, register_proc=reg)
        if s.get("_cancel"):
            return
        s["privileged"] = priv
        out = []
        total = max(len(hosts), 1)
        for i, h in enumerate(hosts):
            hd = host_to_dict(h)
            findings = []
            for svc in h.services:
                if svc.product:
                    for f in lookup(svc.product, svc.version):
                        findings.append({**finding_to_dict(f), "port": svc.port})
            hd["findings"] = findings
            out.append(hd)
            s["progress"] = {"percent": round(100 * (i + 1) / total, 1), "phase": "CVE correlation", "eta": ""}
        s["hosts"] = out
        s["progress"] = {"percent": 100.0, "phase": "complete", "eta": ""}
        s["status"] = "complete"
        log("scan complete.")
    except Exception as e:
        if not s.get("_cancel"):
            s["status"] = "error"
            s["error"] = str(e)
            s["_log"].append(f"ERROR: {e}")
    finally:
        _PROCS.pop(sid, None)
        if s["status"] != "cancelled":
            s["_end"] = _now()
            s["finished_at"] = _iso(s["_end"])
            if s["status"] == "complete":
                try:
                    if STORAGE.persist_completed_scan(s):
                        s["changes"] = STORAGE.record_drift(s)
                except Exception as e:
                    _LOGGER.exception("NetRecon persistence failed: scan_id=%s path=%s", sid, STORAGE.path)
                    s["status"] = "error"
                    s["error"] = f"persistence failed: {e}"
                    s["_log"].append(f"ERROR: {s['error']}")


@app.post("/probe")
def create_probe(req: ProbeRequest):
    auth = Authorization(req.authorized_by, req.engagement_id, req.allowed_cidrs)
    try:
        enforce([req.ip], auth)
    except OutOfScopeError as e:
        raise HTTPException(403, str(e))
    if req.depth not in ("quick", "standard", "thorough"):
        raise HTTPException(400, f"Unknown depth '{req.depth}'.")
    pid = uuid.uuid4().hex[:12]
    _PROBES[pid] = {
        "probe_id": pid, "status": "queued", "ip": req.ip, "depth": req.depth, "host": None, "error": None,
        "started_at": None, "finished_at": None, "progress": {"percent": 0.0, "phase": "queued", "eta": ""},
        "_start": None, "_end": None, "_log": deque(maxlen=200),
    }
    threading.Thread(target=_run_probe, args=(pid, req.ip, req.depth, req.skip_ping), daemon=True).start()
    return {"probe_id": pid, "status": "queued", "ip": req.ip}


@app.get("/probe/{pid}")
def get_probe(pid):
    p = _PROBES.get(pid)
    if not p:
        raise HTTPException(404, "probe not found")
    return _pub(p)


@app.post("/probe/{pid}/cancel")
def cancel_probe(pid):
    p = _PROBES.get(pid)
    if not p:
        raise HTTPException(404, "probe not found")
    if p["status"] in ("complete", "error", "cancelled"):
        return _pub(p)
    p["_cancel"] = True
    _kill(pid)
    p["status"] = "cancelled"
    p["_end"] = _now()
    p["finished_at"] = _iso(p["_end"])
    return _pub(p)


def _run_probe(pid, ip, depth, skip_ping):
    p = _PROBES[pid]
    p["status"] = "scanning"
    p["_start"] = _now()
    p["started_at"] = _iso(p["_start"])

    def prog(pc, ph, e):
        p["progress"] = {"percent": round(pc, 1), "phase": ph, "eta": e}

    def log(l):
        p["_log"].append(f"{datetime.now().strftime('%H:%M:%S')}  {l}")

    def reg(pr):
        _PROCS[pid] = pr

    try:
        host = probe_host(ip, depth=depth, skip_ping=skip_ping, progress_cb=prog, log_cb=log, register_proc=reg)
        if p.get("_cancel"):
            return
        if host is None:
            p["status"] = "complete"
            p["error"] = "Host did not respond (try depth=thorough)."
        else:
            for svc in host.get("services", []):
                if svc.get("product"):
                    for f in lookup(svc["product"], svc.get("version", "")):
                        svc.setdefault("findings", []).append(finding_to_dict(f))
            p["host"] = host
            p["status"] = "complete"
        p["progress"] = {"percent": 100.0, "phase": "complete", "eta": ""}
    except Exception as e:
        if not p.get("_cancel"):
            p["status"] = "error"
            p["error"] = str(e)
    finally:
        _PROCS.pop(pid, None)
        if p["status"] != "cancelled":
            p["_end"] = _now()
            p["finished_at"] = _iso(p["_end"])
