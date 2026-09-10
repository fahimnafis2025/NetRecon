import unittest

from backend.risk import PORT_SEVERITY_OVERRIDES, score_port, severity_for_score


class RiskTests(unittest.TestCase):
    def test_port_overrides(self):
        expected = {
            445: ("HIGH", 70), 3389: ("HIGH", 70), 23: ("HIGH", 70),
            5900: ("HIGH", 70), 21: ("MEDIUM", 50), 22: ("LOW", 25),
        }
        for port, result in expected.items():
            self.assertEqual(PORT_SEVERITY_OVERRIDES[port], result[0])
            self.assertEqual(score_port(port), result[1])

    def test_score_severity_bands(self):
        self.assertEqual(severity_for_score(0), "INFO")
        self.assertEqual(severity_for_score(39), "LOW")
        self.assertEqual(severity_for_score(40), "MEDIUM")
        self.assertEqual(severity_for_score(70), "HIGH")
        self.assertEqual(severity_for_score(90), "CRITICAL")

    def test_unknown_port_has_low_default_score(self):
        self.assertEqual(score_port(12345), 20)


if __name__ == "__main__":
    unittest.main()
