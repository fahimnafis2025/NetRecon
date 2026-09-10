import unittest

from backend.drift import detect_changes


class DriftTests(unittest.TestCase):
    def host(self, ip="192.0.2.10", mac="aa:bb:cc:dd:ee:ff", ports=(80,)):
        return {
            "ip": ip,
            "mac": mac,
            "hostname": "host",
            "vendor": "Example",
            "device_type": "server",
            "confidence": "high",
            "services": [{"port": p, "protocol": "tcp", "state": "open"} for p in ports],
        }

    def scan(self, scan_id, hosts, coverage="top-1000"):
        return {"scan_id": scan_id, "engagement_id": "E1", "finished_at": scan_id,
                "hosts": hosts, "coverage_signature": {"ports": coverage}}

    def test_new_device_and_new_port(self):
        changes = detect_changes(self.scan("one", [self.host(ports=(80,))]),
                                 self.scan("two", [self.host(ports=(80, 445)), self.host(mac="11:22:33:44:55:66")]), {})
        self.assertEqual({event["event_type"] for event in changes}, {"new_device", "new_port"})
        port = next(event for event in changes if event["event_type"] == "new_port")
        self.assertEqual((port["severity"], port["risk_score"]), ("HIGH", 70))

    def test_closed_port_requires_coverage(self):
        baseline = self.scan("one", [self.host(ports=(80, 443))], "top-1000")
        current = self.scan("two", [self.host(ports=(80,))], "top-1000")
        changes = detect_changes(baseline, current, {})
        self.assertEqual([event["port"] for event in changes if event["event_type"] == "closed_port"], [443])

        limited = self.scan("three", [self.host(ports=(80,))], "top-100")
        self.assertFalse(any(event["event_type"] == "closed_port" for event in detect_changes(current, limited, {})))

    def test_possible_disappeared_then_disappeared(self):
        baseline = self.scan("one", [self.host()])
        first = self.scan("two", [])
        second = self.scan("three", [])
        statuses = {}
        first_changes = detect_changes(baseline, first, statuses)
        self.assertEqual(first_changes[0]["event_type"], "possible_disappeared")
        statuses["mac:aabbccddeeff"] = 1
        second_changes = detect_changes(baseline, second, statuses)
        self.assertEqual(second_changes[0]["event_type"], "device_disappeared")

    def test_reappeared_resets_status(self):
        baseline = self.scan("one", [self.host()])
        current = self.scan("two", [self.host()])
        changes = detect_changes(baseline, current, {"mac:aabbccddeeff": 2})
        self.assertEqual(changes[0]["event_type"], "reappeared_device")
        self.assertEqual(changes[0]["severity"], "LOW")
        self.assertEqual(changes[0]["risk_score"], 15)


if __name__ == "__main__":
    unittest.main()
