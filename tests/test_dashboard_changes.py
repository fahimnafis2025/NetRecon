import unittest
from pathlib import Path


class ChangeExplorerDashboardTests(unittest.TestCase):
    def test_change_explorer_contract(self):
        html = (Path(__file__).parents[1] / "frontend" / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('id="changeExplorer"', html)
        self.assertIn('id="changeTable"', html)
        self.assertIn("history/changes", html)
        self.assertIn("renderChangesHistory", html)


if __name__ == "__main__":
    unittest.main()
