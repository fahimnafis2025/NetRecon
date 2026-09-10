import unittest
from pathlib import Path

from backend import main


class Phase4CompletionTests(unittest.TestCase):
    def setUp(self):
        self.dashboard = (Path(__file__).parents[1] / "frontend" / "dashboard.html").read_text(encoding="utf-8")

    def test_version_is_250(self):
        self.assertEqual(main.app.version, "2.5.0")
        self.assertIn("v2.5", self.dashboard)

    def test_sidebar_is_spa_navigation(self):
        self.assertIn('data-view="scan"', self.dashboard)
        self.assertIn("function switchView(view)", self.dashboard)
        self.assertIn("event.preventDefault()", self.dashboard)
        self.assertIn("view-hidden", self.dashboard)

    def test_all_final_views_exist(self):
        for view_id in ("scan", "inventory", "ports", "probe", "findings", "assetExplorer", "scanHistory", "changeExplorer", "riskOverview", "map"):
            self.assertIn(f'id="{view_id}"', self.dashboard)

    def test_no_phase_four_packaging_files(self):
        root = Path(__file__).parents[1]
        self.assertFalse((root / "packaging").exists())
        self.assertFalse((root / "installer").exists())


if __name__ == "__main__":
    unittest.main()
