import unittest
from pathlib import Path


class AssetTimelineDashboardTests(unittest.TestCase):
    def test_asset_timeline_contract(self):
        html = (Path(__file__).parents[1] / "frontend" / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('id="assetTimeline"', html)
        self.assertIn('id="timelineList"', html)
        self.assertIn("history/assets/\"+assetId+\"/timeline", html)
        self.assertIn("renderTimeline", html)


if __name__ == "__main__":
    unittest.main()
