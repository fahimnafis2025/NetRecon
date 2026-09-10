import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from backend.storage import Storage, default_db_path


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "netrecon.db"
        self.storage = Storage(self.db_path)

    def tearDown(self):
        self.tempdir.cleanup()

    def scan(self, scan_id="scan-1", status="complete", finished_at="2026-09-10T12:00:00+00:00", hosts=None):
        return {
            "scan_id": scan_id,
            "status": status,
            "profile": "safe",
            "targets": ["192.0.2.0/24"],
            "modifiers": [],
            "engagement_id": "ENG-1",
            "created_at": "2026-09-10T11:55:00+00:00",
            "started_at": "2026-09-10T11:56:00+00:00",
            "finished_at": finished_at,
            "privileged": True,
            "_authorized_by": "operator@example.test",
            "_authorization_note": "authorized test",
            "_allowed_cidrs": ["192.0.2.0/24"],
            "hosts": hosts or [],
        }

    def host(self, ip="192.0.2.10", mac="AA:BB:CC:DD:EE:FF"):
        return {
            "ip": ip,
            "hostname": "router",
            "mac": mac,
            "vendor": "Example",
            "device_type": "router / AP",
            "confidence": "high",
            "services": [{"port": 443, "protocol": "tcp", "state": "open"}],
            "findings": [{"cve_id": "CVE-TEST", "severity": "LOW"}],
        }

    def connect(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return closing(connection)

    @unittest.skipIf(os.name == "nt", "POSIX default path test requires a POSIX runtime")
    def test_default_root_path(self):
        with patch.dict(os.environ, {}, clear=True), patch("backend.storage.os.name", "posix"), \
                patch("backend.storage.Path.home", return_value=Path("/root")):
            self.assertEqual(default_db_path(), Path("/root/.local/share/NetRecon/netrecon.db"))

    @unittest.skipIf(os.name == "nt", "POSIX default path test requires a POSIX runtime")
    def test_default_normal_user_path(self):
        with patch.dict(os.environ, {}, clear=True), patch("backend.storage.os.name", "posix"), \
                patch("backend.storage.Path.home", return_value=Path("/home/operator")):
            self.assertEqual(default_db_path(), Path("/home/operator/.local/share/NetRecon/netrecon.db"))

    def test_netrecon_db_override(self):
        with patch.dict(os.environ, {"NETRECON_DB": "/var/lib/netrecon/custom.db"}, clear=True):
            self.assertEqual(default_db_path(), Path("/var/lib/netrecon/custom.db"))

    def test_database_info_reports_writable_status(self):
        info = self.storage.database_info()

        self.assertEqual(info["enabled"], True)
        self.assertEqual(info["path"], str(self.db_path))
        self.assertEqual(info["schema_version"], 2)
        self.assertEqual(info["writable"], True)

        self.storage.initialize()
        initialized_info = self.storage.database_info()
        self.assertEqual(initialized_info["schema_version"], 2)
        self.assertEqual(initialized_info["writable"], True)

    def test_schema_is_created_with_required_tables_and_fields(self):
        self.storage.initialize()

        with self.connect() as connection:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )}
            self.assertTrue({"schema_meta", "scans", "assets", "asset_observations"} <= tables)
            asset_columns = {row[1] for row in connection.execute("PRAGMA table_info(assets)")}
            self.assertTrue({"first_seen_at", "last_seen_at", "risk_score", "risk_severity"} <= asset_columns)

    def test_completed_scan_survives_reopening_storage(self):
        self.assertTrue(self.storage.persist_completed_scan(self.scan(hosts=[self.host()])))
        reopened = Storage(self.db_path)
        self.assertTrue(reopened.persist_completed_scan(self.scan(scan_id="scan-2", finished_at="2026-09-10T13:00:00+00:00", hosts=[self.host()])))

        with self.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM asset_observations").fetchone()[0], 2)

    def test_first_seen_is_preserved_and_last_seen_updates(self):
        self.storage.persist_completed_scan(self.scan(hosts=[self.host()]))
        updated = self.host()
        updated["hostname"] = "router-new-name"
        self.storage.persist_completed_scan(self.scan(scan_id="scan-2", finished_at="2026-09-10T13:00:00+00:00", hosts=[updated]))

        with self.connect() as connection:
            row = connection.execute(
                "SELECT first_seen_at, first_seen_scan_id, last_seen_at, last_seen_scan_id, last_hostname FROM assets"
            ).fetchone()
            self.assertEqual(row["first_seen_at"], "2026-09-10T12:00:00+00:00")
            self.assertEqual(row["first_seen_scan_id"], "scan-1")
            self.assertEqual(row["last_seen_at"], "2026-09-10T13:00:00+00:00")
            self.assertEqual(row["last_seen_scan_id"], "scan-2")
            self.assertEqual(row["last_hostname"], "router-new-name")

    def test_multiple_assets_and_observations_are_stored(self):
        hosts = [self.host(), self.host(ip="192.0.2.11", mac="11:22:33:44:55:66")]
        self.storage.persist_completed_scan(self.scan(hosts=hosts))

        with self.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 2)
            observation = connection.execute(
                "SELECT services_json, findings_json, active FROM asset_observations LIMIT 1"
            ).fetchone()
            self.assertEqual(json.loads(observation["services_json"])[0]["port"], 443)
            self.assertEqual(json.loads(observation["findings_json"])[0]["cve_id"], "CVE-TEST")
            self.assertEqual(observation["active"], 1)

    def test_non_completed_scans_are_not_persisted(self):
        for status in ("queued", "scanning", "error", "cancelled"):
            self.assertFalse(self.storage.persist_completed_scan(self.scan(scan_id=status, status=status)))

        self.storage.initialize()
        with self.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 0)

    def test_risk_fields_are_nullable_for_phase_two(self):
        self.storage.persist_completed_scan(self.scan(hosts=[self.host()]))

        with self.connect() as connection:
            row = connection.execute("SELECT risk_score, risk_severity FROM assets").fetchone()
            self.assertIsNone(row["risk_score"])
            self.assertIsNone(row["risk_severity"])

    def test_phase_three_schema_migrates_existing_phase_two_database(self):
        with closing(self.storage._connect()) as connection:
            with connection:
                connection.executescript(
                    """
                    CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL, applied_at TEXT NOT NULL);
                    INSERT INTO schema_meta VALUES (1, 1, '2026-09-10T00:00:00+00:00');
                    CREATE TABLE scans (scan_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, authorized_by TEXT NOT NULL,
                        authorization_note TEXT NOT NULL, allowed_cidrs_json TEXT NOT NULL, targets_json TEXT NOT NULL,
                        profile TEXT NOT NULL, modifiers_json TEXT NOT NULL, status TEXT NOT NULL,
                        privileged INTEGER, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT NOT NULL);
                    CREATE TABLE assets (asset_id INTEGER PRIMARY KEY, engagement_id TEXT NOT NULL, stable_key TEXT NOT NULL,
                        first_seen_at TEXT NOT NULL, first_seen_scan_id TEXT NOT NULL, last_seen_at TEXT NOT NULL,
                        last_seen_scan_id TEXT NOT NULL, last_ip TEXT, last_hostname TEXT, last_mac TEXT, last_vendor TEXT,
                        last_device_type TEXT, last_confidence TEXT, risk_score REAL, risk_severity TEXT);
                    CREATE TABLE asset_observations (observation_id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL,
                        asset_id INTEGER NOT NULL, observed_at TEXT NOT NULL, ip TEXT, hostname TEXT, vendor TEXT,
                        device_type TEXT, confidence TEXT, active INTEGER NOT NULL, services_json TEXT NOT NULL,
                        findings_json TEXT NOT NULL);
                    """
                )

        self.storage.initialize()

        with self.connect() as connection:
            self.assertEqual(connection.execute("SELECT schema_version FROM schema_meta").fetchone()[0], 2)
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )}
            self.assertTrue({"drift_events", "asset_status"} <= tables)

    def test_record_drift_persists_new_port_and_asset_risk(self):
        first = self.scan(hosts=[self.host()])
        first["coverage_signature"] = {"ports": "top-1000"}
        second_host = self.host()
        second_host["services"].append({"port": 445, "protocol": "tcp", "state": "open"})
        second = self.scan(scan_id="scan-2", finished_at="2026-09-10T13:00:00+00:00", hosts=[second_host])
        second["coverage_signature"] = {"ports": "top-1000"}

        self.storage.persist_completed_scan(first)
        self.storage.record_drift(first)
        self.storage.persist_completed_scan(second)
        changes = self.storage.record_drift(second)

        self.assertEqual(len(changes["new_ports"]), 1)
        self.assertEqual(changes["new_ports"][0]["severity"], "HIGH")
        with self.connect() as connection:
            event = connection.execute("SELECT event_type, severity, risk_score FROM drift_events").fetchone()
            asset = connection.execute("SELECT risk_score, risk_severity FROM assets").fetchone()
            self.assertEqual((event["event_type"], event["severity"], event["risk_score"]), ("new_port", "HIGH", 70))
            self.assertEqual((asset["risk_score"], asset["risk_severity"]), (70.0, "HIGH"))


if __name__ == "__main__":
    unittest.main()
