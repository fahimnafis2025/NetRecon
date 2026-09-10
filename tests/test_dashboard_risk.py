import unittest
from pathlib import Path


class RiskOverviewDashboardTests(unittest.TestCase):
    def test_risk_overview_contract(self):
        html = (Path(__file__).parents[1] / "frontend" / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('id="riskOverview"', html)
        self.assertIn('id="riskTable"', html)
        self.assertIn("history/risk", html)
        self.assertIn("renderRiskOverview", html)


if __name__ == "__main__":
    unittest.main()
