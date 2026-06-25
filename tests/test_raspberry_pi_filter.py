from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lan_inventory_scan_pi import (
    expand_to_24_chunks,
    filter_raspberry_pis,
    format_duration,
    load_checkpoint,
    load_avahi_browse_hostnames,
    load_dhcp_lease_hostnames,
    is_likely_raspberry_pi,
    parse_nmap_xml,
    save_checkpoint,
    scan_chunks,
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


class HostnameResolutionTests(unittest.TestCase):
    def test_loads_dnsmasq_lease_hostnames(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp:
            temp.write(
                "1719300000 b8:27:eb:12:34:56 10.42.0.54 "
                "mirror-pi 01:b8:27:eb:12:34:56\n"
            )
            temp.write(
                "1719300001 dc:a6:32:12:34:56 10.42.0.134 "
                "* 01:dc:a6:32:12:34:56\n"
            )
            lease_path = temp.name

        try:
            self.assertEqual(
                load_dhcp_lease_hostnames([lease_path]), {"10.42.0.54": "mirror-pi"}
            )
        finally:
            Path(lease_path).unlink(missing_ok=True)

    def test_loads_avahi_browse_hostnames(self):
        avahi_output = (
            "=;wlan0;IPv4;mirror-pi SSH;_ssh._tcp;local;"
            "mirror-pi.local;10.42.0.54;22;\n"
        )
        with mock.patch(
            "lan_inventory_scan_pi.shutil.which", return_value="avahi-browse"
        ), mock.patch("lan_inventory_scan_pi.subprocess.run") as mocked_run:
            mocked_run.return_value.returncode = 0
            mocked_run.return_value.stdout = avahi_output

            self.assertEqual(
                load_avahi_browse_hostnames(), {"10.42.0.54": "mirror-pi.local"}
            )

    def test_parse_nmap_xml_uses_dhcp_lease_hostname_when_dns_is_missing(self):
        xml = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <status state=\"up\"/>
    <address addr=\"10.42.0.54\" addrtype=\"ipv4\"/>
    <address
      addr=\"B8:27:EB:12:34:56\"
      addrtype=\"mac\"
      vendor=\"Raspberry Pi Trading Ltd\"
    />
    <hostnames/>
  </host>
</nmaprun>
"""
        with mock.patch("lan_inventory_scan_pi.reverse_dns", return_value=""), mock.patch(
            "lan_inventory_scan_pi.load_dhcp_lease_hostnames",
            return_value={"10.42.0.54": "mirror-pi"},
        ), mock.patch(
            "lan_inventory_scan_pi.load_avahi_browse_hostnames", return_value={}
        ), mock.patch("lan_inventory_scan_pi.resolve_avahi_address") as mocked_avahi:
            rows = parse_nmap_xml(xml)

        self.assertEqual(rows[0]["hostname"], "mirror-pi")
        mocked_avahi.assert_not_called()

    def test_parse_nmap_xml_falls_back_to_avahi_for_unknown_hotspot_host(self):
        xml = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <status state=\"up\"/>
    <address addr=\"10.42.0.175\" addrtype=\"ipv4\"/>
    <hostnames/>
  </host>
</nmaprun>
"""
        with mock.patch("lan_inventory_scan_pi.reverse_dns", return_value=""), mock.patch(
            "lan_inventory_scan_pi.load_dhcp_lease_hostnames", return_value={}
        ), mock.patch(
            "lan_inventory_scan_pi.load_avahi_browse_hostnames", return_value={}
        ), mock.patch(
            "lan_inventory_scan_pi.resolve_avahi_address", return_value="sensor-pi.local"
        ):
            rows = parse_nmap_xml(xml)

        self.assertEqual(rows[0]["hostname"], "sensor-pi.local")

    def test_parse_nmap_xml_uses_avahi_browse_before_per_host_avahi_lookup(self):
        xml = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <status state=\"up\"/>
    <address addr=\"10.42.0.54\" addrtype=\"ipv4\"/>
    <hostnames/>
  </host>
</nmaprun>
"""
        with mock.patch("lan_inventory_scan_pi.reverse_dns", return_value=""), mock.patch(
            "lan_inventory_scan_pi.load_dhcp_lease_hostnames", return_value={}
        ), mock.patch(
            "lan_inventory_scan_pi.load_avahi_browse_hostnames",
            return_value={"10.42.0.54": "mirror-pi.local"},
        ), mock.patch("lan_inventory_scan_pi.resolve_avahi_address") as mocked_avahi:
            rows = parse_nmap_xml(xml)

        self.assertEqual(rows[0]["hostname"], "mirror-pi.local")
        mocked_avahi.assert_not_called()

    def test_parse_nmap_xml_uses_dns_name_as_hostname_fallback(self):
        xml = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <status state=\"up\"/>
    <address addr=\"192.168.1.200\" addrtype=\"ipv4\"/>
    <hostnames/>
  </host>
</nmaprun>
"""
        with mock.patch("lan_inventory_scan_pi.reverse_dns", return_value="cm5.attlocal.net"), mock.patch(
            "lan_inventory_scan_pi.load_dhcp_lease_hostnames", return_value={}
        ), mock.patch(
            "lan_inventory_scan_pi.load_avahi_browse_hostnames", return_value={}
        ), mock.patch("lan_inventory_scan_pi.resolve_avahi_address") as mocked_avahi:
            rows = parse_nmap_xml(xml)

        self.assertEqual(rows[0]["hostname"], "cm5.attlocal.net")
        self.assertEqual(rows[0]["dns_name"], "cm5.attlocal.net")
        mocked_avahi.assert_not_called()


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

    def test_completed_checkpoint_starts_fresh_scan_by_default(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            checkpoint_path = temp.name

        try:
            old_hosts = {
                "192.168.1.10": {
                    "ip_address": "192.168.1.10",
                    "hostname": "old-pi",
                    "dns_name": "",
                    "mac_address": "",
                    "manufacturer": "",
                }
            }
            save_checkpoint(checkpoint_path, {"192.168.1.0/24"}, old_hosts)

            new_rows = [
                {
                    "ip_address": "192.168.1.20",
                    "hostname": "new-pi",
                    "dns_name": "",
                    "mac_address": "",
                    "manufacturer": "",
                }
            ]
            with mock.patch(
                "lan_inventory_scan_pi.scan_chunk",
                return_value=("192.168.1.0/24", new_rows),
            ) as mocked_scan:
                combined = scan_chunks(
                    chunks=["192.168.1.0/24"],
                    timeout_s=10,
                    workers=1,
                    checkpoint_path=checkpoint_path,
                    resume=True,
                )

            mocked_scan.assert_called_once()
            self.assertEqual(combined, {"192.168.1.20": new_rows[0]})
        finally:
            Path(checkpoint_path).unlink(missing_ok=True)

    def test_chunk_timeouts_share_global_scan_budget(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            checkpoint_path = temp.name

        observed_timeouts = []

        def fake_scan(chunk, timeout_s):
            observed_timeouts.append(timeout_s)
            return chunk, []

        try:
            with mock.patch("lan_inventory_scan_pi.scan_chunk", side_effect=fake_scan):
                scan_chunks(
                    chunks=["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"],
                    timeout_s=30,
                    workers=1,
                    checkpoint_path=checkpoint_path,
                    resume=False,
                )

            self.assertEqual(len(observed_timeouts), 3)
            self.assertTrue(all(timeout <= 30 for timeout in observed_timeouts))
            self.assertGreater(observed_timeouts[0], observed_timeouts[-1])
        finally:
            Path(checkpoint_path).unlink(missing_ok=True)

    def test_format_duration(self):
        self.assertEqual(format_duration(65), "1m 5s")


if __name__ == "__main__":
    unittest.main()
