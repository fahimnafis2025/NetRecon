import unittest
from unittest.mock import Mock, patch

try:
    from backend import main
except ModuleNotFoundError as error:
    main = None
    MAIN_IMPORT_ERROR = error
else:
    MAIN_IMPORT_ERROR = None


@unittest.skipUnless(main is not None, "FastAPI dependencies are not installed: %s" % MAIN_IMPORT_ERROR)
class PersistenceIntegrationTests(unittest.TestCase):
    def scan_state(self, scan_id="scan-1"):
        return {
            "scan_id": scan_id,
            "status": "queued",
            "profile": "safe",
            "targets": ["192.0.2.10"],
            "engagement_id": "ENG-1",
            "created_at": "2026-09-10T12:00:00+00:00",
            "started_at": None,
            "finished_at": None,
            "privileged": None,
            "progress": {"percent": 0.0, "phase": "queued", "eta": ""},
            "hosts": [],
            "error": None,
            "_start": None,
            "_end": None,
            "_log": [],
            "_authorized_by": "operator@example.test",
            "_authorization_note": "authorized test",
            "_allowed_cidrs": ["192.0.2.0/24"],
        }

    def run_scan_state(self, state, result):
        main._SCANS[state["scan_id"]] = state
        try:
            with patch.object(main, "run_scan", return_value=result):
                main._run(state["scan_id"], state["targets"], state["profile"], [], None)
        finally:
            main._SCANS.pop(state["scan_id"], None)

    def test_successful_scan_persists_once_after_completion(self):
        storage = Mock()
        storage.persist_completed_scan.return_value = True
        state = self.scan_state()

        with patch.object(main, "STORAGE", storage):
            self.run_scan_state(state, ([], True))

        storage.persist_completed_scan.assert_called_once()
        storage.record_drift.assert_called_once()
        self.assertEqual(storage.persist_completed_scan.call_args.args[0]["status"], "complete")

    def test_failed_scan_does_not_persist(self):
        storage = Mock()
        state = self.scan_state()

        with patch.object(main, "STORAGE", storage), patch.object(main, "run_scan", side_effect=RuntimeError("test failure")):
            main._SCANS[state["scan_id"]] = state
            try:
                main._run(state["scan_id"], state["targets"], state["profile"], [], None)
            finally:
                main._SCANS.pop(state["scan_id"], None)

        storage.persist_completed_scan.assert_not_called()

    def test_persistence_failure_is_logged(self):
        storage = Mock()
        storage.persist_completed_scan.side_effect = RuntimeError("database unavailable")
        state = self.scan_state()

        with patch.object(main, "STORAGE", storage), patch.object(main, "_LOGGER") as logger:
            self.run_scan_state(state, ([], True))

        logger.exception.assert_called_once()
        self.assertIn("NetRecon persistence failed", logger.exception.call_args.args[0])
        self.assertEqual(state["status"], "error")

    def test_health_exposes_database_info(self):
        info = {"enabled": True, "path": "/tmp/netrecon.db", "schema_version": 1, "writable": True}
        with patch.object(main.STORAGE, "database_info", return_value=info):
            result = main.health()

        self.assertEqual(result["database"], info)


if __name__ == "__main__":
    unittest.main()
