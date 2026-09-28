import unittest
from unittest import mock

import lan_inventory_scan_pi as scan_pi


class ConnectionTypeTests(unittest.TestCase):
    def test_classifies_common_interface_names(self):
        self.assertEqual(scan_pi.classify_interface_connection_type("eth0"), "Ethernet")
        self.assertEqual(scan_pi.classify_interface_connection_type("enp3s0"), "Ethernet")
        self.assertEqual(scan_pi.classify_interface_connection_type("wlan0"), "Wifi")
        self.assertEqual(scan_pi.classify_interface_connection_type("docker0"), "Unknown")
        self.assertEqual(scan_pi.classify_interface_connection_type(""), "Unknown")

    def test_get_connection_type_uses_route_interface(self):
        completed = mock.Mock(returncode=0, stdout="192.168.1.42 dev wlan0 src 192.168.1.2 uid 1000\n")
        with mock.patch("lan_inventory_scan_pi.subprocess.run", return_value=completed):
            self.assertEqual(scan_pi.get_connection_type("192.168.1.42"), "Wifi")

    def test_get_connection_type_returns_unknown_on_route_failure(self):
        completed = mock.Mock(returncode=1, stdout="")
        with mock.patch("lan_inventory_scan_pi.subprocess.run", return_value=completed):
            self.assertEqual(scan_pi.get_connection_type("10.0.0.99"), "Unknown")


class RouteParsingTests(unittest.TestCase):
    def test_parse_default_interface(self):
        output = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
        self.assertEqual(scan_pi._parse_default_interface(output), "eth0")

    def test_parse_ip_addr(self):
        output = "2: eth0    inet 192.168.1.42/24 brd 192.168.1.255 scope global eth0\n"
        self.assertEqual(scan_pi._parse_ip_addr(output), "192.168.1.42/24")

    def test_get_active_network_cidr_builds_network_from_interface_and_address(self):
        route_cp = mock.Mock(returncode=0, stdout="default via 192.168.1.1 dev eth0\n")
        addr_cp = mock.Mock(returncode=0, stdout="2: eth0    inet 192.168.1.42/24 scope global eth0\n")

        with mock.patch("lan_inventory_scan_pi.platform.system", return_value="Linux"), mock.patch(
            "lan_inventory_scan_pi.require_tool"
        ), mock.patch("lan_inventory_scan_pi.subprocess.run", side_effect=[route_cp, addr_cp]):
            self.assertEqual(scan_pi.get_active_network_cidr(), "192.168.1.0/24")

    def test_get_active_network_cidr_rejects_non_linux(self):
        with mock.patch("lan_inventory_scan_pi.platform.system", return_value="Darwin"):
            with self.assertRaises(RuntimeError):
                scan_pi.get_active_network_cidr()

    def test_get_scan_networks_adds_private_routes(self):
        with mock.patch(
            "lan_inventory_scan_pi.get_active_network_cidr", return_value="192.168.1.0/24"
        ), mock.patch(
            "lan_inventory_scan_pi.subprocess.run",
            return_value=mock.Mock(
                returncode=0,
                stdout="10.42.0.0/24 dev wlan0 proto kernel scope link\ndefault via 192.168.1.1 dev eth0\n",
            ),
        ):
            networks = scan_pi.get_scan_networks()

        self.assertEqual(networks, ["10.42.0.0/24", "192.168.1.0/24"])


class WorkerCountTests(unittest.TestCase):
    def test_rejects_non_positive_workers(self):
        args = scan_pi.parse_args(["--workers", "0"])
        with self.assertRaises(ValueError):
            scan_pi.get_worker_count(args)

    def test_no_prompt_default_timeout_used_without_flag(self):
        args = scan_pi.parse_args([])
        self.assertEqual(args.timeout, scan_pi.DEFAULT_DISCOVERY_TIMEOUT)
        self.assertEqual(args.enrich_timeout, scan_pi.DEFAULT_ENRICH_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
