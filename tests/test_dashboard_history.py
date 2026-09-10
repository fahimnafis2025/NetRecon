import unittest
from pathlib import Path


DASHBOARD = Path(__file__).parents[1] / "frontend" / "dashboard.html"


class DashboardHistoryTests(unittest.TestCase):
    def read(self):
        return DASHBOARD.read_text(encoding="utf-8")

    def test_asset_explorer_contract(self):
        html = self.read()
        self.assertIn('id="assetExplorer"', html)
        self.assertIn('id="assetTable"', html)
        self.assertIn("history/assets", html)
        self.assertIn("renderAssets", html)


if __name__ == "__main__":
    unittest.main()
