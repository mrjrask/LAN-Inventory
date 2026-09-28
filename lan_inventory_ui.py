#!/usr/bin/env python3
"""Terminal UI: a live-updating scan view plus a sortable/searchable browser.

Two pieces, both usable without any third-party dependency (curses,
rich, textual, ...) so the scanners stay pip-install-free everywhere:

* ``LiveScanView`` redraws an in-place progress bar and host table while
  the scan runs (falls back to plain status lines when stdout is not a
  TTY, e.g. piped output or CI logs).
* ``run_browser`` is a small REPL you land in once the scan finishes,
  with ``sort``/``search``/``pis``/``csv`` commands over the full result
  set. It reads from stdin so it is skipped automatically when stdin is
  not a TTY (no dangling prompt in non-interactive runs).

``run_interactive_scan`` wires the two-phase core engine
(discover -> estimate -> enrich) to ``LiveScanView`` so every platform
entry point gets the same experience with one call.
"""
import sys
import time
from typing import Dict, List, Optional, TextIO, Tuple

from lan_inventory_core import (
    OUTPUT_CSV,
    ConnectionTypeFn,
    _SORTABLE_COLUMN_KEYS,  # internal but intentionally shared with the browser
    discover_chunks,
    enrich_hosts,
    estimate_enrichment_seconds,
    filter_raspberry_pis,
    filter_rows,
    format_duration,
    format_table,
    sort_rows,
    write_csv,
)

MAX_LIVE_ROWS = 20


def render_progress_bar(done: int, total: int, width: int = 30) -> str:
    fraction = 1.0 if total <= 0 else min(1.0, done / total)
    filled = int(width * fraction)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {fraction * 100:5.1f}%"


class LiveScanView:
    """Redraws an in-place progress bar and host table on a TTY.

    On a non-TTY stream (piped output, log files, CI) it prints one plain
    status line per update instead of trying to move the cursor, so
    behavior stays deterministic outside an interactive terminal.
    """

    def __init__(self, stream: Optional[TextIO] = None, max_rows: int = MAX_LIVE_ROWS):
        self.stream = stream or sys.stdout
        self.max_rows = max_rows
        self.interactive = bool(getattr(self.stream, "isatty", lambda: False)())
        self._last_frame_lines = 0
        self._start_time = time.time()

    def _clear_previous_frame(self) -> None:
        if not self.interactive or not self._last_frame_lines:
            return
        self.stream.write(f"\x1b[{self._last_frame_lines}A")
        self.stream.write("\x1b[J")

    def _emit(self, lines: List[str]) -> None:
        if self.interactive:
            self._clear_previous_frame()
            self.stream.write("\n".join(lines) + "\n")
            self.stream.flush()
            self._last_frame_lines = len(lines)
        else:
            self.stream.write(lines[0] + "\n")
            self.stream.flush()

    def discovery_progress(self, finished: int, total: int, host_count: int) -> None:
        elapsed = time.time() - self._start_time
        header = (
            f"Discovering hosts: {render_progress_bar(finished, total)} "
            f"{finished}/{total} subnet chunk(s) | {host_count} host(s) found | "
            f"elapsed {format_duration(elapsed)}"
        )
        self._emit([header])

    def enrichment_progress(
        self, rows: Dict[str, Dict[str, str]], finished: int, total: int, eta_seconds: float
    ) -> None:
        elapsed = time.time() - self._start_time
        remaining = max(0.0, eta_seconds - elapsed)
        header = (
            f"Gathering details: {render_progress_bar(finished, total)} "
            f"{finished}/{total} host(s) | elapsed {format_duration(elapsed)} | "
            f"ETA {format_duration(remaining)}"
        )
        if not self.interactive:
            self._emit([header])
            return

        ordered = sort_rows(list(rows.values()), "ip")
        shown = ordered[-self.max_rows :]
        lines = [header, ""]
        if shown:
            lines.append(format_table(shown))
            if len(ordered) > len(shown):
                lines.append(f"... and {len(ordered) - len(shown)} more (full list after the scan completes)")
        else:
            lines.append("(no hosts enriched yet)")
        self._emit(lines)

    def finish(self) -> None:
        if self.interactive:
            self.stream.write("\n")
            self.stream.flush()
        self._last_frame_lines = 0


def run_interactive_scan(
    chunks: List[str],
    discovery_timeout: float,
    discovery_workers: int,
    enrich_timeout: float,
    enrich_workers: int,
    checkpoint_path: str,
    resume: bool,
    get_connection_type: ConnectionTypeFn,
    view: Optional[LiveScanView] = None,
) -> Dict[str, Dict[str, str]]:
    """Run discovery, estimate the enrichment time, then enrich -- driving
    a LiveScanView through both phases so results populate as they arrive."""
    view = view or LiveScanView()

    discovered_so_far: Dict[str, Dict[str, str]] = {}

    def _on_chunk_done(_chunk: str, rows: List[Dict[str, str]], finished: int, total: int) -> None:
        for row in rows:
            discovered_so_far.setdefault(row["ip_address"], row)
        view.discovery_progress(finished, total, len(discovered_so_far))

    discovered = discover_chunks(
        chunks=chunks,
        timeout_s=discovery_timeout,
        workers=discovery_workers,
        checkpoint_path=checkpoint_path,
        resume=resume,
        on_chunk_done=_on_chunk_done,
    )
    view.finish()

    basic_rows = list(discovered.values())
    print(f"Discovery complete: {len(basic_rows)} host(s) found across {len(chunks)} subnet chunk(s).")
    if not basic_rows:
        return {}

    print("Estimating enrichment time using a sample of hosts...")
    eta_seconds = estimate_enrichment_seconds(basic_rows, enrich_workers, get_connection_type)
    print(
        f"Estimated time to gather full details for {len(basic_rows)} host(s): "
        f"~{format_duration(eta_seconds)} using {enrich_workers} worker(s)."
    )

    enrich_view = LiveScanView(stream=view.stream)
    enriched_so_far: Dict[str, Dict[str, str]] = {}

    def _on_host_done(row: Dict[str, str], finished: int, total: int) -> None:
        enriched_so_far[row["ip_address"]] = row
        enrich_view.enrichment_progress(enriched_so_far, finished, total, eta_seconds)

    enriched = enrich_hosts(
        basic_rows=basic_rows,
        workers=enrich_workers,
        timeout_s=enrich_timeout,
        get_connection_type=get_connection_type,
        on_host_done=_on_host_done,
    )
    enrich_view.finish()
    return enriched


# --------------------------------------------------------------------------
# Post-scan interactive browser: sortable + searchable command prompt
# --------------------------------------------------------------------------

HELP_TEXT = """
Commands:
  sort <column> [desc]   Sort by column: ip, hostname, dns, mac, vendor, connection
  search <text>          Filter rows containing text in any column (case-insensitive)
  clear                  Clear the current search filter
  pis                    Show only likely Raspberry Pi devices
  all                    Show all discovered hosts (clears the Raspberry Pi filter)
  csv [path]             Write the currently filtered/sorted rows to a CSV file
  help                   Show this help
  quit / exit / q        Exit the browser
""".strip()


class BrowserState:
    def __init__(self, rows: List[Dict[str, str]]):
        self.all_rows = rows
        self.sort_column = "ip"
        self.sort_reverse = False
        self.search_query = ""
        self.pi_only = False

    def visible_rows(self) -> List[Dict[str, str]]:
        rows = self.all_rows
        if self.pi_only:
            rows = filter_raspberry_pis(rows)
        rows = filter_rows(rows, self.search_query)
        rows = sort_rows(rows, self.sort_column, self.sort_reverse)
        return rows


def process_command(state: BrowserState, command: str) -> Tuple[bool, str]:
    """Apply a single browser command. Returns (should_continue, message)."""
    command = command.strip()
    if not command:
        return True, ""
    parts = command.split(maxsplit=2)
    verb = parts[0].lower()

    if verb in ("quit", "exit", "q"):
        return False, "Exiting browser."

    if verb == "help":
        return True, HELP_TEXT

    if verb == "sort":
        if len(parts) < 2:
            return True, "Usage: sort <column> [desc]"
        column = parts[1].lower()
        if column not in _SORTABLE_COLUMN_KEYS:
            return True, f"Unknown column '{column}'. Choose from: {', '.join(_SORTABLE_COLUMN_KEYS)}"
        state.sort_column = column
        state.sort_reverse = len(parts) > 2 and parts[2].lower().startswith("desc")
        return True, f"Sorted by {column}{' (descending)' if state.sort_reverse else ''}."

    if verb == "search":
        state.search_query = command[len("search") :].strip()
        return True, (f"Filtering for '{state.search_query}'." if state.search_query else "Search cleared.")

    if verb == "clear":
        state.search_query = ""
        return True, "Search cleared."

    if verb == "pis":
        state.pi_only = True
        return True, "Showing only likely Raspberry Pi devices."

    if verb == "all":
        state.pi_only = False
        return True, "Showing all discovered hosts."

    if verb == "csv":
        path = parts[1] if len(parts) > 1 else OUTPUT_CSV
        write_csv(state.visible_rows(), path)
        return True, f"Wrote {len(state.visible_rows())} row(s) to {path}."

    return True, f"Unknown command '{verb}'. Type 'help' for a list of commands."


def run_browser(
    rows: List[Dict[str, str]],
    input_stream: Optional[TextIO] = None,
    output_stream: Optional[TextIO] = None,
) -> None:
    input_stream = input_stream or sys.stdin
    output_stream = output_stream or sys.stdout
    state = BrowserState(rows)

    output_stream.write("\nInteractive result browser. Type 'help' for commands, 'quit' to exit.\n")
    while True:
        visible = state.visible_rows()
        output_stream.write(format_table(visible) + "\n")
        output_stream.write(f"({len(visible)} of {len(state.all_rows)} host(s) shown)\n")
        output_stream.write("> ")
        output_stream.flush()
        line = input_stream.readline()
        if not line:
            break
        keep_going, message = process_command(state, line)
        if message:
            output_stream.write(message + "\n")
        if not keep_going:
            break
