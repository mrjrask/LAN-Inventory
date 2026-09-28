import unittest
from unittest import mock

import lan_inventory_scan_macos as scan_macos


class RouteAndIfconfigParsingTests(unittest.TestCase):
    def test_parse_route_get_interface(self):
        output = "   route to: default\ndestination: default\n       mask: default\n  interface: en0\n"
        self.assertEqual(scan_macos._parse_route_get_interface(output), "en0")

    def test_parse_ifconfig_inet_with_hex_netmask(self):
        output = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n"
            "\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n"
        )
        ip, netmask = scan_macos._parse_ifconfig_inet(output)
        self.assertEqual(ip, "192.168.1.42")
        self.assertEqual(netmask, "0xffffff00")

    def test_netmask_to_prefixlen_hex(self):
        self.assertEqual(scan_macos._netmask_to_prefixlen("0xffffff00"), 24)

    def test_netmask_to_prefixlen_dotted(self):
        self.assertEqual(scan_macos._netmask_to_prefixlen("255.255.255.0"), 24)

    def test_get_active_network_cidr_combines_route_and_ifconfig(self):
        route_cp = mock.Mock(returncode=0, stdout="  interface: en0\n")
        ifconfig_cp = mock.Mock(returncode=0, stdout="\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n")

        with mock.patch("lan_inventory_scan_macos.platform.system", return_value="Darwin"), mock.patch(
            "lan_inventory_scan_macos.require_tool"
        ), mock.patch("lan_inventory_scan_macos.subprocess.run", side_effect=[route_cp, ifconfig_cp]):
            self.assertEqual(scan_macos.get_active_network_cidr(), "192.168.1.0/24")

    def test_get_active_network_cidr_rejects_non_macos(self):
        with mock.patch("lan_inventory_scan_macos.platform.system", return_value="Linux"):
            with self.assertRaises(RuntimeError):
                scan_macos.get_active_network_cidr()


class HardwarePortClassificationTests(unittest.TestCase):
    def test_classifies_wifi_and_ethernet_from_hardware_port_map(self):
        hardware_ports = {"en0": "Wi-Fi", "en1": "USB 10/100/1000 LAN"}
        self.assertEqual(scan_macos.classify_interface_connection_type("en0", hardware_ports), "Wifi")
        self.assertEqual(scan_macos.classify_interface_connection_type("en1", hardware_ports), "Ethernet")

    def test_unknown_interface_returns_unknown(self):
        self.assertEqual(scan_macos.classify_interface_connection_type("utun3", {}), "Unknown")
        self.assertEqual(scan_macos.classify_interface_connection_type("", {}), "Unknown")

    def test_load_hardware_port_map_parses_networksetup_output(self):
        output = (
            "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n\n"
            "Hardware Port: Thunderbolt Ethernet\nDevice: en1\nEthernet Address: 11:22:33:44:55:66\n\n"
        )
        scan_macos._load_hardware_port_map.cache_clear()
        with mock.patch("lan_inventory_scan_macos.shutil.which", return_value="/usr/sbin/networksetup"), mock.patch(
            "lan_inventory_scan_macos.subprocess.run", return_value=mock.Mock(returncode=0, stdout=output)
        ):
            mapping = scan_macos._load_hardware_port_map()

        self.assertEqual(mapping, {"en0": "Wi-Fi", "en1": "Thunderbolt Ethernet"})
        scan_macos._load_hardware_port_map.cache_clear()

    def test_get_connection_type_uses_route_and_hardware_map(self):
        route_cp = mock.Mock(returncode=0, stdout="  interface: en0\n")
        with mock.patch("lan_inventory_scan_macos.subprocess.run", return_value=route_cp), mock.patch(
            "lan_inventory_scan_macos._load_hardware_port_map", return_value={"en0": "Wi-Fi"}
        ):
            self.assertEqual(scan_macos.get_connection_type("192.168.1.50"), "Wifi")


class WorkerCountTests(unittest.TestCase):
    def test_rejects_non_positive_workers(self):
        args = scan_macos.parse_args(["--workers", "-1"])
        with self.assertRaises(ValueError):
            scan_macos.get_worker_count(args)


if __name__ == "__main__":
    unittest.main()
