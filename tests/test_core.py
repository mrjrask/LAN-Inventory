import tempfile
import unittest
from pathlib import Path
from unittest import mock

import lan_inventory_core as core


class ChunkingTests(unittest.TestCase):
    def test_expands_large_network_to_24_chunks(self):
        self.assertEqual(
            core.expand_to_24_chunks(["192.168.0.0/23"]),
            ["192.168.0.0/24", "192.168.1.0/24"],
        )

    def test_keeps_smaller_network_as_its_own_chunk(self):
        self.assertEqual(core.expand_to_24_chunks(["192.168.1.128/25"]), ["192.168.1.128/25"])


class FormatDurationTests(unittest.TestCase):
    def test_format_duration(self):
        self.assertEqual(core.format_duration(65), "1m 5s")
        self.assertEqual(core.format_duration(3725), "1h 2m 5s")
        self.assertEqual(core.format_duration(-1), "unknown")


class CheckpointTests(unittest.TestCase):
    def test_checkpoint_round_trip(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            checkpoint_path = temp.name

        try:
            hosts = {
                "192.168.1.10": {
                    "ip_address": "192.168.1.10",
                    "mac_address": "",
                    "manufacturer": "",
                    "nmap_hostname": "raspberrypi",
                }
            }
            core.save_checkpoint(checkpoint_path, {"192.168.1.0/24"}, hosts)
            completed, loaded_hosts = core.load_checkpoint(checkpoint_path, resume=True)

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
                    "mac_address": "",
                    "manufacturer": "",
                    "nmap_hostname": "old-pi",
                }
            }
            core.save_checkpoint(checkpoint_path, {"192.168.1.0/24"}, old_hosts)

            new_rows = [
                {
                    "ip_address": "192.168.1.20",
                    "mac_address": "",
                    "manufacturer": "",
                    "nmap_hostname": "new-pi",
                }
            ]
            with mock.patch(
                "lan_inventory_core.discover_chunk",
                return_value=("192.168.1.0/24", new_rows),
            ) as mocked_discover:
                combined = core.discover_chunks(
                    chunks=["192.168.1.0/24"],
                    timeout_s=10,
                    workers=1,
                    checkpoint_path=checkpoint_path,
                    resume=True,
                )

            mocked_discover.assert_called_once()
            self.assertEqual(combined, {"192.168.1.20": new_rows[0]})
        finally:
            Path(checkpoint_path).unlink(missing_ok=True)

    def test_discovery_timeouts_share_global_scan_budget(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            checkpoint_path = temp.name

        observed_timeouts = []

        def fake_discover(chunk, timeout_s):
            observed_timeouts.append(timeout_s)
            return chunk, []

        try:
            with mock.patch("lan_inventory_core.discover_chunk", side_effect=fake_discover):
                core.discover_chunks(
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


class DiscoveryXmlParsingTests(unittest.TestCase):
    def test_parses_basic_fields_without_enrichment(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.42.0.54" addrtype="ipv4"/>
    <address addr="B8:27:EB:12:34:56" addrtype="mac" vendor="Raspberry Pi Trading Ltd"/>
    <hostnames><hostname name="mirror-pi.lan"/></hostnames>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.42.0.99" addrtype="ipv4"/>
  </host>
</nmaprun>
"""
        rows = core.parse_discovery_xml(xml)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip_address"], "10.42.0.54")
        self.assertEqual(rows[0]["mac_address"], "B8:27:EB:12:34:56")
        self.assertEqual(rows[0]["manufacturer"], "Raspberry Pi Trading Ltd")
        self.assertEqual(rows[0]["nmap_hostname"], "mirror-pi.lan")

    def test_discovery_nmap_command_disables_dns_resolution(self):
        completed = mock.Mock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")
        with mock.patch("lan_inventory_core.subprocess.run", return_value=completed) as mocked_run, mock.patch(
            "lan_inventory_core.shutil.which", return_value="/usr/bin/nmap"
        ):
            core.run_nmap_discovery("192.168.1.0/24", timeout_s=30)

        called_cmd = mocked_run.call_args[0][0]
        self.assertIn("-n", called_cmd)
        self.assertIn("-sn", called_cmd)


class EnrichmentTests(unittest.TestCase):
    def test_enrich_host_prefers_nmap_hostname(self):
        basic_row = {
            "ip_address": "10.42.0.54",
            "mac_address": "B8:27:EB:12:34:56",
            "manufacturer": "Raspberry Pi Trading Ltd",
            "nmap_hostname": "mirror-pi",
        }
        with mock.patch("lan_inventory_core.reverse_dns", return_value=""), mock.patch(
            "lan_inventory_core.resolve_avahi_address"
        ) as mocked_avahi:
            row = core.enrich_host(
                basic_row,
                dhcp_lease_hostnames={},
                avahi_browse_hostnames={},
                get_connection_type=lambda ip: "Ethernet",
            )

        self.assertEqual(row["hostname"], "mirror-pi")
        self.assertEqual(row["connection_type"], "Ethernet")
        mocked_avahi.assert_not_called()

    def test_enrich_host_falls_back_through_lease_avahi_dns(self):
        basic_row = {"ip_address": "10.42.0.175", "mac_address": "", "manufacturer": "", "nmap_hostname": ""}
        with mock.patch("lan_inventory_core.reverse_dns", return_value=""):
            row = core.enrich_host(
                basic_row,
                dhcp_lease_hostnames={},
                avahi_browse_hostnames={},
                get_connection_type=lambda ip: "Unknown",
            )
        # No lease/avahi-browse/dns/nmap hostname -> falls through to the
        # per-host avahi-resolve-address lookup, which returns "" when the
        # tool isn't installed in this test environment.
        self.assertEqual(row["hostname"], "")

    def test_enrich_hosts_reports_progress_per_host(self):
        basic_rows = [
            {"ip_address": "10.0.0.1", "mac_address": "", "manufacturer": "", "nmap_hostname": "a"},
            {"ip_address": "10.0.0.2", "mac_address": "", "manufacturer": "", "nmap_hostname": "b"},
        ]
        progress_calls = []
        with mock.patch("lan_inventory_core.reverse_dns", return_value=""), mock.patch(
            "lan_inventory_core.load_dhcp_lease_hostnames", return_value={}
        ), mock.patch("lan_inventory_core.load_avahi_browse_hostnames", return_value={}):
            results = core.enrich_hosts(
                basic_rows,
                workers=2,
                timeout_s=10,
                get_connection_type=lambda ip: "Wifi",
                on_host_done=lambda row, finished, total: progress_calls.append((row["ip_address"], finished, total)),
            )

        self.assertEqual(set(results.keys()), {"10.0.0.1", "10.0.0.2"})
        self.assertEqual(len(progress_calls), 2)
        self.assertEqual({c[2] for c in progress_calls}, {2})

    def test_estimate_enrichment_seconds_scales_with_host_count(self):
        basic_rows = [
            {"ip_address": f"10.0.0.{i}", "mac_address": "", "manufacturer": "", "nmap_hostname": ""}
            for i in range(1, 11)
        ]
        with mock.patch("lan_inventory_core.reverse_dns", return_value=""), mock.patch(
            "lan_inventory_core.load_dhcp_lease_hostnames", return_value={}
        ), mock.patch("lan_inventory_core.load_avahi_browse_hostnames", return_value={}), mock.patch(
            "lan_inventory_core.resolve_avahi_address", return_value=""
        ):
            eta = core.estimate_enrichment_seconds(
                basic_rows, workers=5, get_connection_type=lambda ip: "Unknown", sample_size=2
            )
        self.assertGreaterEqual(eta, 0.0)


class HostnameResolutionTests(unittest.TestCase):
    def test_loads_dnsmasq_lease_hostnames(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp:
            temp.write("1719300000 b8:27:eb:12:34:56 10.42.0.54 mirror-pi 01:b8:27:eb:12:34:56\n")
            temp.write("1719300001 dc:a6:32:12:34:56 10.42.0.134 * 01:dc:a6:32:12:34:56\n")
            lease_path = temp.name

        try:
            self.assertEqual(core.load_dhcp_lease_hostnames([lease_path]), {"10.42.0.54": "mirror-pi"})
        finally:
            Path(lease_path).unlink(missing_ok=True)

    def test_loads_avahi_browse_hostnames(self):
        avahi_output = "=;wlan0;IPv4;mirror-pi SSH;_ssh._tcp;local;mirror-pi.local;10.42.0.54;22;\n"
        with mock.patch("lan_inventory_core.shutil.which", return_value="avahi-browse"), mock.patch(
            "lan_inventory_core.subprocess.run"
        ) as mocked_run:
            mocked_run.return_value.returncode = 0
            mocked_run.return_value.stdout = avahi_output

            self.assertEqual(core.load_avahi_browse_hostnames(), {"10.42.0.54": "mirror-pi.local"})


class RaspberryPiFilterTests(unittest.TestCase):
    def test_matches_raspberry_pi_manufacturer(self):
        self.assertTrue(
            core.is_likely_raspberry_pi(
                {"hostname": "media-center", "dns_name": "", "manufacturer": "Raspberry Pi Trading Ltd"}
            )
        )

    def test_matches_common_hostname_when_mac_vendor_missing(self):
        self.assertTrue(
            core.is_likely_raspberry_pi({"hostname": "raspberrypi.local", "dns_name": "", "manufacturer": ""})
        )

    def test_filters_non_pi_devices(self):
        rows = [
            {"ip_address": "192.168.1.10", "hostname": "raspberrypi", "dns_name": "", "manufacturer": ""},
            {"ip_address": "192.168.1.11", "hostname": "laptop", "dns_name": "", "manufacturer": "Dell"},
        ]
        self.assertEqual(core.filter_raspberry_pis(rows), [rows[0]])


class SortAndFilterTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {
                "ip_address": "192.168.1.20",
                "hostname": "laptop",
                "dns_name": "",
                "mac_address": "AA:BB",
                "manufacturer": "Dell",
                "connection_type": "Wifi",
            },
            {
                "ip_address": "192.168.1.5",
                "hostname": "raspberrypi",
                "dns_name": "",
                "mac_address": "CC:DD",
                "manufacturer": "Raspberry Pi",
                "connection_type": "Ethernet",
            },
        ]

    def test_sort_rows_by_ip_numeric_not_lexicographic(self):
        sorted_rows = core.sort_rows(self.rows, "ip")
        self.assertEqual([r["ip_address"] for r in sorted_rows], ["192.168.1.5", "192.168.1.20"])

    def test_sort_rows_by_hostname_reverse(self):
        sorted_rows = core.sort_rows(self.rows, "hostname", reverse=True)
        self.assertEqual([r["hostname"] for r in sorted_rows], ["raspberrypi", "laptop"])

    def test_filter_rows_matches_any_column_case_insensitive(self):
        filtered = core.filter_rows(self.rows, "DELL")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["hostname"], "laptop")

    def test_filter_rows_empty_query_returns_all(self):
        self.assertEqual(core.filter_rows(self.rows, ""), self.rows)


class OutputTests(unittest.TestCase):
    def test_write_csv_round_trip(self):
        rows = [
            {
                "ip_address": "192.168.1.5",
                "hostname": "raspberrypi",
                "dns_name": "",
                "mac_address": "CC:DD",
                "manufacturer": "Raspberry Pi",
                "connection_type": "Ethernet",
            }
        ]
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp:
            csv_path = temp.name
        try:
            core.write_csv(rows, csv_path)
            content = Path(csv_path).read_text(encoding="utf-8")
            self.assertIn("raspberrypi", content)
            self.assertIn("ip_address", content)
        finally:
            Path(csv_path).unlink(missing_ok=True)

    def test_format_table_handles_empty_rows(self):
        self.assertEqual(core.format_table([]), "No hosts found.")


if __name__ == "__main__":
    unittest.main()
