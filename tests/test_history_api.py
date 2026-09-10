import unittest
from unittest.mock import patch, Mock
from fastapi import HTTPException

from backend import main
from backend.storage import Storage


class HistoryQueryTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tempdir = tempfile.TemporaryDirectory()
        self.storage = Storage(Path(self.tempdir.name) / "history.db")

    def tearDown(self):
        self.tempdir.cleanup()

    def scan(self, scan_id, engagement="E1", finished_at=None, hosts=None):
        return {
            "scan_id": scan_id, "status": "complete", "profile": "safe",
            "targets": ["192.0.2.0/24"], "engagement_id": engagement,
            "created_at": finished_at or scan_id, "started_at": finished_at or scan_id,
            "finished_at": finished_at or scan_id, "privileged": True,
            "_authorized_by": "tester", "_authorization_note": "",
            "_allowed_cidrs": ["192.0.2.0/24"], "_modifiers": [],
            "hosts": hosts or [], "coverage_signature": {"ports": "top-1000"},
        }

    def host(self, ip="192.0.2.10", mac="aa:bb:cc:dd:ee:ff"):
        return {"ip": ip, "hostname": "host", "mac": mac, "vendor": "Example",
                "device_type": "server", "confidence": "high", "active": True,
                "services": [{"port": 445, "protocol": "tcp", "state": "open"}],
                "findings": []}

    def seed(self):
        first = self.scan("scan-1", finished_at="2026-09-10T12:00:00+00:00", hosts=[self.host()])
        second = self.scan("scan-2", finished_at="2026-09-10T13:00:00+00:00", hosts=[self.host()])
        self.storage.persist_completed_scan(first)
        self.storage.record_drift(first)
        self.storage.persist_completed_scan(second)
        self.storage.record_drift(second)

    def test_scan_history_and_asset_queries(self):
        self.seed()
        scans = self.storage.list_history_scans("E1")
        assets = self.storage.list_history_assets("E1")
        self.assertEqual([row["scan_id"] for row in scans], ["scan-2", "scan-1"])
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["first_seen_at"], "2026-09-10T12:00:00+00:00")

    def test_asset_timeline_and_changes_queries(self):
        self.seed()
        asset_id = self.storage.list_history_assets("E1")[0]["asset_id"]
        self.assertEqual(len(self.storage.asset_timeline("E1", asset_id)), 2)
        self.assertIsInstance(self.storage.list_history_changes("E1"), list)

    def test_history_queries_are_engagement_isolated(self):
        self.seed()
        other = self.scan("other", engagement="E2", hosts=[self.host(ip="198.51.100.10", mac="11:22:33:44:55:66")])
        self.storage.persist_completed_scan(other)
        self.assertEqual(len(self.storage.list_history_scans("E1")), 2)
        self.assertEqual(len(self.storage.list_history_assets("E1")), 1)
        self.assertEqual(len(self.storage.list_history_scans("E2")), 1)

    def test_risk_overview_reads_stored_values(self):
        self.seed()
        overview = self.storage.history_risk_overview("E1")
        self.assertIn("severity_counts", overview)
        self.assertIn("top_assets", overview)
        self.assertIn("recent_changes", overview)

    def test_history_routes_require_authorized_scope(self):
        with self.assertRaises(HTTPException) as raised:
            main.history_assets("E1", "tester", "")
        self.assertEqual(raised.exception.status_code, 403)

    def test_history_routes_return_read_only_data(self):
        storage = Mock()
        storage.list_history_scans.return_value = [{"scan_id": "scan-1", "targets": ["192.0.2.0/24"]}]
        storage.list_history_assets.return_value = [{"asset_id": 1, "last_ip": "192.0.2.10"}]
        storage.list_history_changes.return_value = [{"event_id": 1, "last_ip": "192.0.2.10"}]
        storage.history_risk_overview.return_value = {"severity_counts": [], "top_assets": [], "recent_changes": []}
        with patch.object(main, "STORAGE", storage):
            params = ("E1", "tester", "192.0.2.0/24")
            self.assertIn("scans", main.history_scans(*params))
            self.assertIn("assets", main.history_assets(*params))
            self.assertIn("changes", main.history_changes(*params))
            self.assertIn("severity_counts", main.history_risk(*params))


if __name__ == "__main__":
    unittest.main()
