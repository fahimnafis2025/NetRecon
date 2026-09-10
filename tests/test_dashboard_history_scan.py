import unittest
from pathlib import Path


class ScanHistoryDashboardTests(unittest.TestCase):
    def test_scan_history_contract(self):
        html = (Path(__file__).parents[1] / "frontend" / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('id="scanHistory"', html)
        self.assertIn('id="scanHistoryTable"', html)
        self.assertIn("history/scans", html)
        self.assertIn("renderScanHistory", html)


if __name__ == "__main__":
    unittest.main()
