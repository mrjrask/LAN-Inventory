import json
import unittest
from unittest import mock

import lan_inventory_scan_windows as scan_windows


class InterfaceJsonParsingTests(unittest.TestCase):
    def test_parses_single_object_as_list(self):
        payload = json.dumps({"IPAddress": "192.168.1.42", "PrefixLength": 24})
        self.assertEqual(scan_windows.parse_interface_info_json(payload), [json.loads(payload)])

    def test_parses_array(self):
        entries = [
            {"IPAddress": "192.168.1.42", "PrefixLength": 24},
            {"IPAddress": "10.0.0.5", "PrefixLength": 8},
        ]
        self.assertEqual(scan_windows.parse_interface_info_json(json.dumps(entries)), entries)

    def test_empty_output_returns_empty_list(self):
        self.assertEqual(scan_windows.parse_interface_info_json(""), [])
        self.assertEqual(scan_windows.parse_interface_info_json("   "), [])


class MediaTypeClassificationTests(unittest.TestCase):
    def test_classifies_wireless(self):
        self.assertEqual(scan_windows.classify_physical_media_type("Native 802.11"), "Wifi")

    def test_classifies_ethernet(self):
        self.assertEqual(scan_windows.classify_physical_media_type("802.3"), "Ethernet")

    def test_unknown_media_type(self):
        self.assertEqual(scan_windows.classify_physical_media_type(""), "Unknown")
        self.assertEqual(scan_windows.classify_physical_media_type(None), "Unknown")


class InterfaceEntryTests(unittest.TestCase):
    def setUp(self):
        self.entries = [
            {
                "IfIndex": 12,
                "IPAddress": "192.168.1.42",
                "PrefixLength": 24,
                "PhysicalMediaType": "Native 802.11",
                "IsDefault": True,
            },
            {
                "IfIndex": 7,
                "IPAddress": "10.10.0.5",
                "PrefixLength": 24,
                "PhysicalMediaType": "802.3",
                "IsDefault": False,
            },
        ]

    def test_get_active_network_cidr_picks_default_entry(self):
        scan_windows._load_interfaces.cache_clear()
        with mock.patch("lan_inventory_scan_windows._run_powershell", return_value=json.dumps(self.entries)):
            self.assertEqual(scan_windows.get_active_network_cidr(), "192.168.1.0/24")
        scan_windows._load_interfaces.cache_clear()

    def test_get_scan_networks_includes_private_subnets(self):
        scan_windows._load_interfaces.cache_clear()
        with mock.patch("lan_inventory_scan_windows._run_powershell", return_value=json.dumps(self.entries)):
            networks = scan_windows.get_scan_networks()
        self.assertEqual(networks, ["10.10.0.0/24", "192.168.1.0/24"])
        scan_windows._load_interfaces.cache_clear()

    def test_get_connection_type_matches_containing_subnet(self):
        scan_windows._load_interfaces.cache_clear()
        with mock.patch("lan_inventory_scan_windows._run_powershell", return_value=json.dumps(self.entries)):
            self.assertEqual(scan_windows.get_connection_type("192.168.1.99"), "Wifi")
            self.assertEqual(scan_windows.get_connection_type("10.10.0.200"), "Ethernet")
            self.assertEqual(scan_windows.get_connection_type("8.8.8.8"), "Unknown")
        scan_windows._load_interfaces.cache_clear()

    def test_get_connection_type_rejects_invalid_ip(self):
        self.assertEqual(scan_windows.get_connection_type("not-an-ip"), "Unknown")


class WorkerCountTests(unittest.TestCase):
    def test_rejects_non_positive_workers(self):
        args = scan_windows.parse_args(["--workers", "0"])
        with self.assertRaises(ValueError):
            scan_windows.get_worker_count(args)


if __name__ == "__main__":
    unittest.main()
