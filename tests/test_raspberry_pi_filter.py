import unittest

from lan_inventory_scan_pi import filter_raspberry_pis, is_likely_raspberry_pi


class RaspberryPiFilterTests(unittest.TestCase):
    def test_matches_raspberry_pi_manufacturer(self):
        self.assertTrue(
            is_likely_raspberry_pi(
                {
                    "hostname": "media-center",
                    "dns_name": "",
                    "manufacturer": "Raspberry Pi Trading Ltd",
                }
            )
        )

    def test_matches_common_hostname_when_mac_vendor_missing(self):
        self.assertTrue(
            is_likely_raspberry_pi(
                {
                    "hostname": "raspberrypi.local",
                    "dns_name": "",
                    "manufacturer": "",
                }
            )
        )

    def test_filters_non_pi_devices(self):
        rows = [
            {"ip_address": "192.168.1.10", "hostname": "raspberrypi", "dns_name": "", "manufacturer": ""},
            {"ip_address": "192.168.1.11", "hostname": "laptop", "dns_name": "", "manufacturer": "Dell"},
        ]

        self.assertEqual(filter_raspberry_pis(rows), [rows[0]])


if __name__ == "__main__":
    unittest.main()
