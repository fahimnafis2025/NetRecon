"""SQLite persistence for completed NetRecon scans."""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from backend.drift import detect_changes
from backend.risk import asset_risk

SCHEMA_VERSION = 2
_LOGGER = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_db_path() -> Path:
    configured = os.getenv("NETRECON_DB")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        base = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "NetRecon" / "netrecon.db"


class Storage:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path).expanduser() if path else default_db_path()
        _LOGGER.info("NetRecon database path: %s", self.path)

    def _connect(self) -> sqlite3.Connection:
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def database_info(self) -> dict[str, Any]:
        schema_version = SCHEMA_VERSION
        writable = False
        try:
            if self.path.exists():
                writable = os.access(self.path, os.W_OK)
                with closing(sqlite3.connect(self.path, timeout=5)) as connection:
                    row = connection.execute(
                        "SELECT schema_version FROM schema_meta WHERE id = 1"
                    ).fetchone()
                    if row is not None:
                        schema_version = int(row[0])
            else:
                parent = self.path.parent
                while not parent.exists() and parent != parent.parent:
                    parent = parent.parent
                writable = os.access(parent, os.W_OK)
        except (OSError, sqlite3.Error):
            writable = False
        return {
            "enabled": True,
            "path": str(self.path),
            "schema_version": schema_version,
            "writable": writable,
        }

    def initialize(self) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.executescript(
                    """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    schema_version INTEGER NOT NULL,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    authorized_by TEXT NOT NULL,
                    authorization_note TEXT NOT NULL,
                    allowed_cidrs_json TEXT NOT NULL,
                    targets_json TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    modifiers_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status = 'complete'),
                    privileged INTEGER,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT NOT NULL,
                    coverage_signature_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS assets (
                    asset_id INTEGER PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    first_seen_scan_id TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    last_seen_scan_id TEXT NOT NULL,
                    last_ip TEXT,
                    last_hostname TEXT,
                    last_mac TEXT,
                    last_vendor TEXT,
                    last_device_type TEXT,
                    last_confidence TEXT,
                    risk_score REAL,
                    risk_severity TEXT,
                    UNIQUE (engagement_id, stable_key),
                    FOREIGN KEY (first_seen_scan_id) REFERENCES scans(scan_id),
                    FOREIGN KEY (last_seen_scan_id) REFERENCES scans(scan_id)
                );

                CREATE TABLE IF NOT EXISTS asset_observations (
                    observation_id INTEGER PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    asset_id INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    ip TEXT,
                    hostname TEXT,
                    mac TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    confidence TEXT,
                    active INTEGER NOT NULL,
                    services_json TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    UNIQUE (scan_id, asset_id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_engagement_finished
                    ON scans (engagement_id, finished_at);
                CREATE INDEX IF NOT EXISTS idx_assets_engagement_key
                    ON assets (engagement_id, stable_key);
                CREATE INDEX IF NOT EXISTS idx_observations_asset_seen
                    ON asset_observations (asset_id, observed_at);
                CREATE INDEX IF NOT EXISTS idx_observations_scan_asset
                    ON asset_observations (scan_id, asset_id);
                CREATE TABLE IF NOT EXISTS asset_status (
                    asset_id INTEGER PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    last_confirmed_scan_id TEXT,
                    last_confirmed_at TEXT,
                    missed_compatible_scans INTEGER NOT NULL DEFAULT 0,
                    current_status TEXT NOT NULL,
                    status_changed_at TEXT NOT NULL,
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS drift_events (
                    event_id INTEGER PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    current_scan_id TEXT NOT NULL,
                    baseline_scan_id TEXT,
                    asset_id INTEGER,
                    event_type TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    port INTEGER,
                    protocol TEXT,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    details_json TEXT NOT NULL,
                    FOREIGN KEY (current_scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
                    FOREIGN KEY (baseline_scan_id) REFERENCES scans(scan_id),
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
                );
                CREATE INDEX IF NOT EXISTS idx_drift_engagement_detected
                    ON drift_events (engagement_id, detected_at);
                CREATE INDEX IF NOT EXISTS idx_drift_current_scan
                    ON drift_events (current_scan_id);
                CREATE INDEX IF NOT EXISTS idx_drift_asset_type
                    ON drift_events (asset_id, event_type);
                CREATE INDEX IF NOT EXISTS idx_asset_status_engagement_status
                    ON asset_status (engagement_id, current_status);
                """
                )
                columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
                if "coverage_signature_json" not in columns:
                    connection.execute(
                        "ALTER TABLE scans ADD COLUMN coverage_signature_json TEXT NOT NULL DEFAULT '{}'"
                    )
                row = connection.execute(
                    "SELECT schema_version FROM schema_meta WHERE id = 1"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO schema_meta (id, schema_version, applied_at) VALUES (1, ?, ?)",
                        (SCHEMA_VERSION, _now_iso()),
                    )
                elif row["schema_version"] == 1:
                    connection.execute(
                        "UPDATE schema_meta SET schema_version = ?, applied_at = ? WHERE id = 1",
                        (SCHEMA_VERSION, _now_iso()),
                    )
                elif row["schema_version"] != SCHEMA_VERSION:
                    raise RuntimeError(
                        "Unsupported NetRecon database schema version: "
                        f"{row['schema_version']}"
                    )
        _LOGGER.info("NetRecon storage initialization succeeded: %s", self.path)

    def persist_completed_scan(self, scan: dict[str, Any]) -> bool:
        if scan.get("status") != "complete":
            return False

        scan_id = scan.get("scan_id")
        finished_at = scan.get("finished_at")
        if not scan_id or not finished_at:
            raise ValueError("completed scans require scan_id and finished_at")

        _LOGGER.info("NetRecon persistence started: scan_id=%s path=%s", scan_id, self.path)
        self.initialize()
        with closing(self._connect()) as connection:
            with connection:
                if connection.execute(
                    "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
                ).fetchone():
                    return False

                connection.execute(
                    """
                INSERT INTO scans (
                    scan_id, engagement_id, authorized_by, authorization_note,
                    allowed_cidrs_json, targets_json, profile, modifiers_json,
                    status, privileged, created_at, started_at, finished_at,
                    coverage_signature_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'complete', ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        scan.get("engagement_id", ""),
                        scan.get("_authorized_by", scan.get("authorized_by", "")),
                        scan.get("_authorization_note", scan.get("note", "")),
                        _json(scan.get("_allowed_cidrs", scan.get("allowed_cidrs", []))),
                        _json(scan.get("targets", [])),
                        scan.get("profile", ""),
                        _json(scan.get("_modifiers", scan.get("modifiers", []))),
                        _bool_int(scan.get("privileged")),
                        scan.get("created_at") or finished_at,
                        scan.get("started_at"),
                        finished_at,
                        _json(scan.get("coverage_signature") or coverage_signature(scan)),
                    ),
                )

                for host in scan.get("hosts", []):
                    asset_id = self._upsert_asset(connection, scan, host, finished_at)
                    connection.execute(
                        """
                    INSERT INTO asset_observations (
                        scan_id, asset_id, observed_at, ip, hostname, mac, vendor,
                        device_type, confidence, active, services_json, findings_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            asset_id,
                            finished_at,
                            host.get("ip"),
                            host.get("hostname", ""),
                            host.get("mac", ""),
                            host.get("vendor", ""),
                            host.get("device_type", "unknown"),
                            host.get("confidence", "low"),
                            _bool_int(host.get("active", True)),
                            _json(host.get("services", [])),
                            _json(host.get("findings", [])),
                        ),
                    )
        _LOGGER.info("NetRecon persistence succeeded: scan_id=%s path=%s", scan_id, self.path)
        return True

    def record_drift(self, scan: dict[str, Any]) -> dict[str, Any]:
        self.initialize()
        with closing(self._connect()) as connection:
            with connection:
                current = self._load_snapshot(connection, scan["scan_id"])
                baseline_row = self._find_baseline(connection, scan, current)
                baseline = self._load_snapshot(connection, baseline_row["scan_id"]) if baseline_row else None
                status_rows = connection.execute(
                    "SELECT a.stable_key, s.missed_compatible_scans FROM asset_status s JOIN assets a ON a.asset_id = s.asset_id WHERE s.engagement_id = ?",
                    (scan.get("engagement_id", ""),),
                ).fetchall()
                statuses = {row["stable_key"]: row["missed_compatible_scans"] for row in status_rows}
                known_hosts = self._last_confirmed_hosts(connection, scan.get("engagement_id", ""))
                changes = detect_changes(baseline, current, statuses, known_hosts=known_hosts)
                asset_ids = {row["stable_key"]: row["asset_id"] for row in connection.execute(
                    "SELECT asset_id, stable_key FROM assets WHERE engagement_id = ?", (scan.get("engagement_id", ""),)
                ).fetchall()}
                for event in changes:
                    event["asset_id"] = event.get("asset_id") or asset_ids.get(event["stable_key"])
                    connection.execute(
                        """INSERT INTO drift_events (engagement_id, current_scan_id, baseline_scan_id, asset_id,
                           event_type, detected_at, port, protocol, severity, risk_score, details_json)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (scan.get("engagement_id", ""), scan["scan_id"], event.get("baseline_scan_id"),
                         event.get("asset_id"), event["event_type"], scan.get("finished_at") or _now_iso(),
                         event.get("port"), event.get("protocol"), event["severity"], event["risk_score"], _json(event)),
                    )
                self._update_asset_statuses(connection, scan, current, changes)
                for host in current.get("hosts", []):
                    score, severity = asset_risk(host, [event for event in changes if event.get("stable_key") == stable_key_for_host(host)])
                    connection.execute(
                        "UPDATE assets SET risk_score = ?, risk_severity = ? WHERE engagement_id = ? AND stable_key = ?",
                        (score, severity, scan.get("engagement_id", ""), stable_key_for_host(host)),
                    )
        return {"baseline_scan_id": baseline.get("scan_id") if baseline else None,
                "new_devices": [e for e in changes if e["event_type"] == "new_device"],
                "possible_disappeared": [e for e in changes if e["event_type"] == "possible_disappeared"],
                "disappeared": [e for e in changes if e["event_type"] == "device_disappeared"],
                "reappeared": [e for e in changes if e["event_type"] == "reappeared_device"],
                "new_ports": [e for e in changes if e["event_type"] == "new_port"],
                "closed_ports": [e for e in changes if e["event_type"] == "closed_port"]}

    def _load_snapshot(self, connection, scan_id: str) -> dict:
        scan = connection.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        hosts = []
        rows = connection.execute("""SELECT o.*, a.asset_id, a.stable_key FROM asset_observations o
            JOIN assets a ON a.asset_id = o.asset_id WHERE o.scan_id = ?""", (scan_id,)).fetchall()
        for row in rows:
            host = {"asset_id": row["asset_id"], "stable_key": row["stable_key"], "ip": row["ip"],
                    "hostname": row["hostname"], "mac": row["mac"], "vendor": row["vendor"],
                    "device_type": row["device_type"], "confidence": row["confidence"],
                    "active": bool(row["active"]), "services": json.loads(row["services_json"]),
                    "findings": json.loads(row["findings_json"])}
            hosts.append(host)
        return {"scan_id": scan["scan_id"], "engagement_id": scan["engagement_id"],
                "finished_at": scan["finished_at"], "hosts": hosts,
                "coverage_signature": json.loads(scan["coverage_signature_json"] or "{}"),
                "targets": json.loads(scan["targets_json"] or "[]"),
                "allowed_cidrs": json.loads(scan["allowed_cidrs_json"] or "[]"),
                "profile": scan["profile"], "modifiers": json.loads(scan["modifiers_json"] or "[]")}

    def _find_baseline(self, connection, scan, current):
        rows = connection.execute(
            "SELECT scan_id FROM scans WHERE engagement_id = ? AND scan_id != ? ORDER BY finished_at DESC",
            (scan.get("engagement_id", ""), scan["scan_id"]),
        ).fetchall()
        for row in rows:
            candidate = self._load_snapshot(connection, row["scan_id"])
            if (candidate["targets"] == current["targets"] and
                    candidate["allowed_cidrs"] == current["allowed_cidrs"]):
                return row
        return None

    def _last_confirmed_hosts(self, connection, engagement_id: str) -> list[dict]:
        rows = connection.execute("""SELECT o.*, a.asset_id, a.stable_key FROM asset_observations o
            JOIN assets a ON a.asset_id = o.asset_id JOIN asset_status s ON s.asset_id = a.asset_id
            WHERE a.engagement_id = ? AND s.current_status != 'active' AND o.scan_id = s.last_confirmed_scan_id""", (engagement_id,)).fetchall()
        return [{"asset_id": row["asset_id"], "stable_key": row["stable_key"], "ip": row["ip"], "mac": row["mac"],
                 "hostname": row["hostname"], "vendor": row["vendor"], "device_type": row["device_type"],
                 "active": True, "services": json.loads(row["services_json"])} for row in rows]

    def _update_asset_statuses(self, connection, scan, current, changes):
        current_keys = {stable_key_for_host(host) for host in current.get("hosts", [])}
        change_by_key = {event["stable_key"]: event for event in changes}
        assets = connection.execute("SELECT asset_id, stable_key FROM assets WHERE engagement_id = ?", (scan.get("engagement_id", ""),)).fetchall()
        for asset in assets:
            key = asset["stable_key"]
            event = change_by_key.get(key)
            if key in current_keys:
                status, missed = "active", 0
                confirmed_at, confirmed_scan = scan.get("finished_at"), scan["scan_id"]
            else:
                previous = connection.execute("SELECT missed_compatible_scans, current_status, last_confirmed_at, last_confirmed_scan_id FROM asset_status WHERE asset_id = ?", (asset["asset_id"],)).fetchone()
                missed = (previous["missed_compatible_scans"] if previous else 0) + 1
                status = "disappeared" if missed >= 2 else "possible_disappeared"
                confirmed_at = previous["last_confirmed_at"] if previous else None
                confirmed_scan = previous["last_confirmed_scan_id"] if previous else None
            connection.execute("""INSERT INTO asset_status (asset_id, engagement_id, last_confirmed_scan_id,
                last_confirmed_at, missed_compatible_scans, current_status, status_changed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(asset_id) DO UPDATE SET last_confirmed_scan_id=excluded.last_confirmed_scan_id,
                last_confirmed_at=excluded.last_confirmed_at, missed_compatible_scans=excluded.missed_compatible_scans,
                current_status=excluded.current_status, status_changed_at=excluded.status_changed_at""",
                (asset["asset_id"], scan.get("engagement_id", ""), confirmed_scan, confirmed_at, missed, status, scan.get("finished_at") or _now_iso()))

    def list_history_scans(self, engagement_id: str, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self.initialize()
        limit = max(1, min(int(limit), 500))
        with closing(self._connect()) as connection:
            rows = connection.execute("""
                SELECT s.scan_id, s.engagement_id, s.profile, s.targets_json, s.finished_at,
                       COUNT(DISTINCT o.asset_id) AS asset_count,
                       COUNT(DISTINCT d.event_id) AS change_count,
                       COALESCE(MAX(d.risk_score), 0) AS highest_change_risk
                FROM scans s
                LEFT JOIN asset_observations o ON o.scan_id = s.scan_id
                LEFT JOIN drift_events d ON d.current_scan_id = s.scan_id
                WHERE s.engagement_id = ?
                GROUP BY s.scan_id
                ORDER BY s.finished_at DESC
                LIMIT ? OFFSET ?
            """, (engagement_id, limit, max(0, int(offset)))).fetchall()
            return [{**dict(row), "targets": json.loads(row["targets_json"] or "[]")} for row in rows]

    def list_history_assets(self, engagement_id: str, status: str | None = None,
                            risk_severity: str | None = None, limit: int = 100,
                            offset: int = 0) -> list[dict[str, Any]]:
        self.initialize()
        clauses = ["a.engagement_id = ?"]
        params: list[Any] = [engagement_id]
        if status:
            clauses.append("COALESCE(st.current_status, 'active') = ?")
            params.append(status)
        if risk_severity:
            clauses.append("a.risk_severity = ?")
            params.append(risk_severity)
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with closing(self._connect()) as connection:
            rows = connection.execute(f"""
                SELECT a.*, COALESCE(st.current_status, 'active') AS current_status,
                       COALESCE(st.missed_compatible_scans, 0) AS missed_compatible_scans
                FROM assets a
                LEFT JOIN asset_status st ON st.asset_id = a.asset_id
                WHERE {' AND '.join(clauses)}
                ORDER BY a.last_seen_at DESC
                LIMIT ? OFFSET ?
            """, params).fetchall()
            return [dict(row) for row in rows]

    def asset_timeline(self, engagement_id: str, asset_id: int) -> list[dict[str, Any]]:
        self.initialize()
        with closing(self._connect()) as connection:
            asset = connection.execute(
                "SELECT 1 FROM assets WHERE asset_id = ? AND engagement_id = ?", (asset_id, engagement_id)
            ).fetchone()
            if not asset:
                return []
            observations = connection.execute("""
                SELECT 'observation' AS item_type, observation_id AS item_id, observed_at AS happened_at,
                       scan_id, ip, hostname, device_type, confidence, services_json, findings_json
                FROM asset_observations WHERE asset_id = ?
            """, (asset_id,)).fetchall()
            events = connection.execute("""
                SELECT 'drift_event' AS item_type, event_id AS item_id, detected_at AS happened_at,
                       current_scan_id AS scan_id, port, protocol, event_type, severity, risk_score, details_json
                FROM drift_events WHERE asset_id = ?
            """, (asset_id,)).fetchall()
            items = [dict(row) for row in observations] + [dict(row) for row in events]
            return sorted(items, key=lambda item: item["happened_at"])

    def list_history_changes(self, engagement_id: str, event_type: str | None = None,
                             severity: str | None = None, limit: int = 100,
                             offset: int = 0) -> list[dict[str, Any]]:
        self.initialize()
        clauses = ["d.engagement_id = ?"]
        params: list[Any] = [engagement_id]
        if event_type:
            clauses.append("d.event_type = ?")
            params.append(event_type)
        if severity:
            clauses.append("d.severity = ?")
            params.append(severity)
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with closing(self._connect()) as connection:
            rows = connection.execute(f"""
                SELECT d.*, a.stable_key, a.last_ip, a.last_hostname
                FROM drift_events d LEFT JOIN assets a ON a.asset_id = d.asset_id
                WHERE {' AND '.join(clauses)}
                ORDER BY d.detected_at DESC LIMIT ? OFFSET ?
            """, params).fetchall()
            return [dict(row) for row in rows]

    def history_risk_overview(self, engagement_id: str) -> dict[str, Any]:
        self.initialize()
        with closing(self._connect()) as connection:
            counts = connection.execute("""
                SELECT COALESCE(risk_severity, 'INFO') AS severity, COUNT(*) AS count
                FROM assets WHERE engagement_id = ? GROUP BY COALESCE(risk_severity, 'INFO')
            """, (engagement_id,)).fetchall()
            assets = connection.execute("""
                SELECT asset_id, stable_key, last_ip, last_hostname, risk_score, risk_severity
                FROM assets WHERE engagement_id = ? ORDER BY risk_score DESC LIMIT 10
            """, (engagement_id,)).fetchall()
            changes = connection.execute("""
                SELECT event_id, asset_id, event_type, severity, risk_score, detected_at, port, protocol
                FROM drift_events WHERE engagement_id = ? ORDER BY risk_score DESC, detected_at DESC LIMIT 10
            """, (engagement_id,)).fetchall()
            return {"severity_counts": [dict(row) for row in counts],
                    "top_assets": [dict(row) for row in assets],
                    "recent_changes": [dict(row) for row in changes]}

    def _upsert_asset(
        self, connection: sqlite3.Connection, scan: dict[str, Any], host: dict[str, Any], observed_at: str
    ) -> int:
        engagement_id = scan.get("engagement_id", "")
        stable_key = stable_asset_key(host)
        existing = connection.execute(
            "SELECT asset_id FROM assets WHERE engagement_id = ? AND stable_key = ?",
            (engagement_id, stable_key),
        ).fetchone()
        fields = (
            observed_at,
            scan["scan_id"],
            host.get("ip"),
            host.get("hostname", ""),
            host.get("mac", ""),
            host.get("vendor", ""),
            host.get("device_type", "unknown"),
            host.get("confidence", "low"),
            host.get("risk_score"),
            host.get("risk_severity"),
        )
        if existing:
            connection.execute(
                """
                UPDATE assets SET
                    last_seen_at = ?, last_seen_scan_id = ?, last_ip = ?,
                    last_hostname = ?, last_mac = ?, last_vendor = ?,
                    last_device_type = ?, last_confidence = ?, risk_score = ?,
                    risk_severity = ?
                WHERE asset_id = ?
                """,
                (*fields, existing["asset_id"]),
            )
            return existing["asset_id"]

        cursor = connection.execute(
            """
            INSERT INTO assets (
                engagement_id, stable_key, first_seen_at, first_seen_scan_id,
                last_seen_at, last_seen_scan_id, last_ip, last_hostname, last_mac,
                last_vendor, last_device_type, last_confidence, risk_score, risk_severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                stable_key,
                observed_at,
                scan["scan_id"],
                *fields,
            ),
        )
        return int(cursor.lastrowid)


def stable_asset_key(host: dict[str, Any]) -> str:
    mac = re.sub(r"[^0-9a-f]", "", str(host.get("mac", "")).lower())
    if mac:
        return f"mac:{mac}"

    identity = "|".join(
        _normalized(host.get(name))
        for name in ("hostname", "vendor", "device_type")
    ).strip("|")
    if identity and identity.replace("|", "") not in ("unknown", "unknownunknown"):
        return f"identity:{identity}"

    return f"ip:{_normalized(host.get('ip'))}"


def stable_key_for_host(host: dict[str, Any]) -> str:
    return stable_asset_key(host)


def _normalized(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else [], separators=(",", ":"), sort_keys=True)


def _bool_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(bool(value))


def coverage_signature(scan: dict[str, Any]) -> dict[str, Any]:
    profile = scan.get("profile", "")
    if profile == "full":
        ports = "all"
    elif profile in ("thorough", "turbo", "validate") or "top_1000" in scan.get("_modifiers", []):
        ports = "top-1000"
    elif profile == "quick":
        ports = "top-100"
    elif profile in ("safe", "discovery"):
        ports = "top-200" if profile == "safe" else "discovery"
    else:
        ports = "unknown"
    return {"profile": profile, "modifiers": list(scan.get("_modifiers", scan.get("modifiers", []))), "ports": ports}
