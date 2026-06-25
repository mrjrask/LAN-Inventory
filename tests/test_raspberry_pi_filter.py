from pathlib import Path
import tempfile
import unittest

from lan_inventory_scan_pi import (
    expand_to_24_chunks,
    filter_raspberry_pis,
    format_duration,
    load_checkpoint,
    is_likely_raspberry_pi,
    save_checkpoint,
)


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


class ChunkScanHelperTests(unittest.TestCase):
    def test_expands_large_network_to_24_chunks(self):
        self.assertEqual(
            expand_to_24_chunks(["192.168.0.0/23"]),
            ["192.168.0.0/24", "192.168.1.0/24"],
        )

    def test_keeps_smaller_network_as_its_own_chunk(self):
        self.assertEqual(expand_to_24_chunks(["192.168.1.128/25"]), ["192.168.1.128/25"])

    def test_checkpoint_round_trip(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            checkpoint_path = temp.name

        try:
            hosts = {
                "192.168.1.10": {
                    "ip_address": "192.168.1.10",
                    "hostname": "raspberrypi",
                    "dns_name": "",
                    "mac_address": "",
                    "manufacturer": "",
                }
            }
            save_checkpoint(checkpoint_path, {"192.168.1.0/24"}, hosts)
            completed, loaded_hosts = load_checkpoint(checkpoint_path, resume=True)

            self.assertEqual(completed, {"192.168.1.0/24"})
            self.assertEqual(loaded_hosts, hosts)
        finally:
            Path(checkpoint_path).unlink(missing_ok=True)

    def test_format_duration(self):
        self.assertEqual(format_duration(65), "1m 5s")


if __name__ == "__main__":
    unittest.main()
