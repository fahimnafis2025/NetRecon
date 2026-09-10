import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.scanner.discovery import _parse_xml, host_to_dict, run_scan


class DiscoveryActivityTests(unittest.TestCase):
    def parse(self, body, **kwargs):
        handle = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
        try:
            handle.write(body.encode("utf-8"))
            handle.close()
            return _parse_xml(handle.name, **kwargs)
        finally:
            Path(handle.name).unlink(missing_ok=True)

    def test_user_set_host_without_open_port_is_rejected(self):
        hosts = self.parse(
            '<nmaprun><host><status state="up" reason="user-set"/>'
            '<address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>'
        )

        self.assertEqual(hosts, [])

    def test_genuine_response_without_open_port_is_accepted(self):
        hosts = self.parse(
            '<nmaprun><host><status state="up" reason="echo-reply"/>'
            '<address addr="192.0.2.11" addrtype="ipv4"/></host></nmaprun>'
        )

        self.assertEqual([host.ip for host in hosts], ["192.0.2.11"])

    def test_open_port_confirms_user_set_host(self):
        hosts = self.parse(
            '<nmaprun><host><status state="up" reason="user-set"/>'
            '<address addr="192.0.2.12" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="443">'
            '<state state="open"/><service name="https"/></port></ports>'
            '</host></nmaprun>'
        )

        self.assertEqual([host.ip for host in hosts], ["192.0.2.12"])
        self.assertEqual([service.port for service in hosts[0].services], [443])

    def test_naabu_confirmed_host_is_accepted(self):
        hosts = self.parse(
            '<nmaprun><host><status state="up" reason="user-set"/>'
            '<address addr="192.0.2.13" addrtype="ipv4"/></host></nmaprun>',
            confirmed_ips={"192.0.2.13"},
        )

        self.assertEqual([host.ip for host in hosts], ["192.0.2.13"])

    def test_skip_ping_preserves_synthetic_probe_result(self):
        hosts = self.parse(
            '<nmaprun><host><status state="up" reason="user-set"/>'
            '<address addr="192.0.2.14" addrtype="ipv4"/></host></nmaprun>',
            allow_synthetic=True,
        )

        self.assertEqual([host.ip for host in hosts], ["192.0.2.14"])

    def test_host_to_dict_preserves_confirmed_host_shape(self):
        hosts = self.parse(
            '<nmaprun><host><status state="up" reason="echo-reply"/>'
            '<address addr="192.0.2.15" addrtype="ipv4"/></host></nmaprun>'
        )

        result = host_to_dict(hosts[0])
        self.assertEqual(result["ip"], "192.0.2.15")
        self.assertIn("services", result)

    def test_nmap_only_scan_passes_empty_confirmation_set(self):
        with patch("backend.scanner.discovery._require_nmap", return_value="nmap"), \
                patch("backend.scanner.discovery._execute"), \
                patch("backend.scanner.discovery._parse_xml", return_value=[]) as parse_xml:
            hosts, privileged = run_scan(["192.0.2.0/24"], profile="discovery")

        self.assertEqual(hosts, [])
        self.assertIsInstance(privileged, bool)
        self.assertEqual(parse_xml.call_args.kwargs["confirmed_ips"], set())


if __name__ == "__main__":
    unittest.main()
