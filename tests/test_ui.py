import io
import unittest
from unittest import mock

import lan_inventory_ui as ui


SAMPLE_ROWS = [
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


class ProgressBarTests(unittest.TestCase):
    def test_full_bar_at_completion(self):
        self.assertIn("100.0%", ui.render_progress_bar(5, 5))

    def test_zero_total_reports_complete(self):
        self.assertIn("100.0%", ui.render_progress_bar(0, 0))

    def test_partial_progress(self):
        bar = ui.render_progress_bar(1, 4)
        self.assertIn("25.0%", bar)


class LiveScanViewNonInteractiveTests(unittest.TestCase):
    def test_plain_stream_prints_single_status_line_per_update(self):
        stream = io.StringIO()
        stream.isatty = lambda: False
        view = ui.LiveScanView(stream=stream)

        view.discovery_progress(finished=1, total=2, host_count=3)
        view.enrichment_progress(rows={}, finished=1, total=3, eta_seconds=10)
        view.finish()

        output_lines = [line for line in stream.getvalue().splitlines() if line]
        self.assertEqual(len(output_lines), 2)
        self.assertIn("Discovering hosts", output_lines[0])
        self.assertIn("Gathering details", output_lines[1])


class BrowserStateTests(unittest.TestCase):
    def test_default_sort_is_by_ip(self):
        state = ui.BrowserState(list(SAMPLE_ROWS))
        visible = state.visible_rows()
        self.assertEqual([r["ip_address"] for r in visible], ["192.168.1.5", "192.168.1.20"])

    def test_pi_only_filter(self):
        state = ui.BrowserState(list(SAMPLE_ROWS))
        state.pi_only = True
        visible = state.visible_rows()
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["hostname"], "raspberrypi")

    def test_search_filter(self):
        state = ui.BrowserState(list(SAMPLE_ROWS))
        state.search_query = "dell"
        visible = state.visible_rows()
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["hostname"], "laptop")


class ProcessCommandTests(unittest.TestCase):
    def setUp(self):
        self.state = ui.BrowserState(list(SAMPLE_ROWS))

    def test_sort_command_changes_column(self):
        keep_going, message = ui.process_command(self.state, "sort hostname")
        self.assertTrue(keep_going)
        self.assertEqual(self.state.sort_column, "hostname")
        self.assertFalse(self.state.sort_reverse)
        self.assertIn("hostname", message)

    def test_sort_command_descending(self):
        ui.process_command(self.state, "sort hostname desc")
        self.assertTrue(self.state.sort_reverse)

    def test_sort_command_rejects_unknown_column(self):
        _keep_going, message = ui.process_command(self.state, "sort bogus")
        self.assertIn("Unknown column", message)
        self.assertEqual(self.state.sort_column, "ip")

    def test_search_command_sets_query(self):
        ui.process_command(self.state, "search raspberry")
        self.assertEqual(self.state.search_query, "raspberry")

    def test_clear_command_resets_query(self):
        self.state.search_query = "something"
        ui.process_command(self.state, "clear")
        self.assertEqual(self.state.search_query, "")

    def test_pis_and_all_commands_toggle_filter(self):
        ui.process_command(self.state, "pis")
        self.assertTrue(self.state.pi_only)
        ui.process_command(self.state, "all")
        self.assertFalse(self.state.pi_only)

    def test_quit_command_stops_loop(self):
        keep_going, _message = ui.process_command(self.state, "quit")
        self.assertFalse(keep_going)

    def test_unknown_command_reports_error_without_stopping(self):
        keep_going, message = ui.process_command(self.state, "bogus")
        self.assertTrue(keep_going)
        self.assertIn("Unknown command", message)

    def test_csv_command_writes_visible_rows(self):
        with mock.patch("lan_inventory_ui.write_csv") as mocked_write:
            ui.process_command(self.state, "csv out.csv")
        mocked_write.assert_called_once()
        written_rows, written_path = mocked_write.call_args[0]
        self.assertEqual(written_path, "out.csv")
        self.assertEqual(len(written_rows), 2)


class RunBrowserTests(unittest.TestCase):
    def test_quit_exits_immediately(self):
        input_stream = io.StringIO("quit\n")
        output_stream = io.StringIO()
        ui.run_browser(SAMPLE_ROWS, input_stream=input_stream, output_stream=output_stream)
        self.assertIn("Exiting browser.", output_stream.getvalue())

    def test_eof_exits_without_error(self):
        input_stream = io.StringIO("")
        output_stream = io.StringIO()
        ui.run_browser(SAMPLE_ROWS, input_stream=input_stream, output_stream=output_stream)
        self.assertIn("Interactive result browser", output_stream.getvalue())

    def test_sort_then_quit_reflects_new_order(self):
        input_stream = io.StringIO("sort hostname\nquit\n")
        output_stream = io.StringIO()
        ui.run_browser(SAMPLE_ROWS, input_stream=input_stream, output_stream=output_stream)
        output = output_stream.getvalue()
        # After sorting by hostname, "laptop" should appear before
        # "raspberrypi" in the second rendered table.
        self.assertLess(output.index("laptop"), output.rindex("raspberrypi"))


class RunInteractiveScanTests(unittest.TestCase):
    def test_wires_discovery_and_enrichment_phases(self):
        basic_row = {"ip_address": "10.0.0.1", "mac_address": "", "manufacturer": "", "nmap_hostname": "host1"}
        enriched_row = {
            "ip_address": "10.0.0.1",
            "hostname": "host1",
            "dns_name": "",
            "mac_address": "",
            "manufacturer": "",
            "connection_type": "Ethernet",
        }

        def fake_discover_chunks(chunks, timeout_s, workers, checkpoint_path, resume, on_chunk_done):
            on_chunk_done("10.0.0.0/24", [basic_row], 1, 1)
            return {"10.0.0.1": basic_row}

        def fake_enrich_hosts(basic_rows, workers, timeout_s, get_connection_type, on_host_done):
            on_host_done(enriched_row, 1, 1)
            return {"10.0.0.1": enriched_row}

        stream = io.StringIO()
        stream.isatty = lambda: False
        view = ui.LiveScanView(stream=stream)

        with mock.patch("lan_inventory_ui.discover_chunks", side_effect=fake_discover_chunks), mock.patch(
            "lan_inventory_ui.enrich_hosts", side_effect=fake_enrich_hosts
        ), mock.patch("lan_inventory_ui.estimate_enrichment_seconds", return_value=1.5):
            result = ui.run_interactive_scan(
                chunks=["10.0.0.0/24"],
                discovery_timeout=30,
                discovery_workers=1,
                enrich_timeout=30,
                enrich_workers=1,
                checkpoint_path="/tmp/does-not-matter.json",
                resume=False,
                get_connection_type=lambda ip: "Ethernet",
                view=view,
            )

        self.assertEqual(result, {"10.0.0.1": enriched_row})


if __name__ == "__main__":
    unittest.main()
