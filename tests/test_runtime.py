import functools
import io
import json
import threading
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import duckdb

from pipeline_runner import (RESULT_SCHEMA, _compact_result_shard, _download_index_shard,
                             _write_result_batch,
                             get_warc_parquet_paths, reset_streaming_run, run_streaming)
from src.runtime import BandwidthLimiter, DashboardServer, RuntimeMonitor, copy_limited
from src.warc_fetcher import WarcFetchError, WarcFetcher


class RecordingLimiter:
    def __init__(self):
        self.amounts = []

    def acquire(self, amount):
        self.amounts.append(amount)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return


class RuntimeTests(unittest.TestCase):
    def test_index_download_retries_403_until_it_succeeds(self):
        error = urllib.error.HTTPError("https://example.test/part-00004.parquet", 403,
                                       "Forbidden", {}, None)
        response = io.BytesIO(b"parquet-data")
        response.status = 200
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            monitor = RuntimeMonitor(str(root / "status.json"), str(root / "scan.log"))
            with mock.patch("pipeline_runner.urllib.request.urlopen",
                            side_effect=[error, response]) as urlopen, \
                    mock.patch("pipeline_runner.time.sleep") as sleep:
                _download_index_shard("https://example.test/part-00004.parquet",
                                      root / "part-00004.parquet", BandwidthLimiter(0), monitor,
                                      cooldown_seconds=1)
            self.assertEqual(urlopen.call_count, 2)
            sleep.assert_called_once_with(1.0)
            self.assertEqual((root / "part-00004.parquet").read_bytes(), b"parquet-data")

    def test_warc_403_starts_shared_cooldown_without_retries(self):
        error = urllib.error.HTTPError("https://example.test/archive.warc.gz", 403,
                                       "Forbidden", {}, None)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("src.warc_fetcher.urllib.request.urlopen", side_effect=error) as urlopen:
                fetcher = WarcFetcher(directory, retries=3, cooldown_seconds=1)
                try:
                    with self.assertRaises(WarcFetchError) as raised:
                        fetcher.fetch("archive.warc.gz", 0, 100)
                finally:
                    fetcher.close()
        self.assertEqual(raised.exception.category, "http_403")
        self.assertEqual(urlopen.call_count, 1)

    def test_fresh_start_removes_only_current_streaming_run(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            args = SimpleNamespace(
                runtime_dir=str(root / "runtime"), output=str(root / "results"),
                cache_dir=str(root / "warc"), state_file=str(root / "status.json"),
                log_file=str(root / "scan.log"),
            )
            crawl = "CC-MAIN-2099-01"
            keep = root / "runtime" / "CC-MAIN-2099-02" / "keep"
            remove = root / "runtime" / crawl / "candidate"
            result = root / "results" / crawl / "part.parquet"
            cache = root / "warc" / "record"
            for path in (keep, remove, result, cache):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")
            Path(args.state_file).write_text("{}", encoding="utf-8")
            Path(args.log_file).write_text("old", encoding="utf-8")

            reset_streaming_run(args, crawl)

            self.assertTrue(keep.exists())
            self.assertFalse((root / "runtime" / crawl).exists())
            self.assertFalse((root / "results" / crawl).exists())
            self.assertFalse(Path(args.cache_dir).exists())
            self.assertFalse(Path(args.state_file).exists())
            self.assertFalse(Path(args.log_file).exists())

    def test_result_batches_keep_optional_column_types_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parts = root / ".parts" / "00000"
            output = root / "part-00000.parquet"
            rows = [{
                "registered_domain": "example.com", "host": "example.com",
                "url": "https://example.com/", "product": "Example",
                "cve_severity": None, "configuration_confidence": None,
            }, {
                "registered_domain": "example.org", "host": "example.org",
                "url": "https://example.org/", "product": "Example",
                "cve_severity": "medium", "configuration_confidence": 0.75,
            }]
            con = duckdb.connect()
            _write_result_batch(con, [rows[0]], parts / "batch-000000.parquet")
            _write_result_batch(con, [rows[1]], parts / "batch-000001.parquet")

            types = []
            for part in sorted(parts.glob("*.parquet")):
                schema = dict((row[0], row[1]) for row in con.execute(
                    "DESCRIBE SELECT * FROM read_parquet(?)", [str(part)]).fetchall())
                types.append((schema["cve_severity"], schema["configuration_confidence"]))
            self.assertEqual(types, [("VARCHAR", "DOUBLE"), ("VARCHAR", "DOUBLE")])

            _compact_result_shard(con, parts, output)
            values = con.execute(
                "SELECT cve_severity, configuration_confidence FROM read_parquet(?) "
                "ORDER BY registered_domain", [str(output)]).fetchall()
            self.assertEqual(values, [(None, None), ("medium", 0.75)])
            self.assertFalse(parts.exists())

    def test_compaction_repairs_legacy_json_varchar_schema_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parts = root / ".parts" / "00000"
            parts.mkdir(parents=True)
            output = root / "part-00000.parquet"
            con = duckdb.connect()

            # Reproduce files produced by the old read_json_auto path: one
            # batch sees only null (JSON), the next sees a string (VARCHAR).
            legacy_rows = [None, "medium"]
            for index, severity in enumerate(legacy_rows):
                jsonl = root / f"legacy-{index}.jsonl"
                row = {name: None for name, _column_type in RESULT_SCHEMA}
                row.update({"registered_domain": f"example{index}.com",
                            "cve_severity": severity})
                jsonl.write_text(json.dumps(row) + "\n", encoding="utf-8")
                con.execute(
                    f"COPY (SELECT * FROM read_json_auto('{jsonl}', "
                    "format='newline_delimited')) TO ? (FORMAT PARQUET)",
                    [str(parts / f"batch-{index:06d}.parquet")])

            schemas = [dict((row[0], row[1]) for row in con.execute(
                "DESCRIBE SELECT * FROM read_parquet(?)", [str(part)]).fetchall())
                for part in sorted(parts.glob("*.parquet"))]
            self.assertEqual([schema["cve_severity"] for schema in schemas],
                             ["JSON", "VARCHAR"])

            _compact_result_shard(con, parts, output)
            self.assertEqual(con.execute(
                "SELECT cve_severity FROM read_parquet(?) ORDER BY registered_domain",
                [str(output)]).fetchall(), [(None,), ("medium",)])

    def test_copy_limited_accounts_for_all_bytes(self):
        limiter = RecordingLimiter()
        destination = io.BytesIO()
        copied = copy_limited(io.BytesIO(b"x" * 100_000), destination, limiter, chunk_size=16_384)
        self.assertEqual(copied, 100_000)
        self.assertEqual(destination.getvalue(), b"x" * 100_000)
        self.assertGreaterEqual(sum(limiter.amounts), copied)

    def test_dashboard_exposes_status_and_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor = RuntimeMonitor(str(Path(directory) / "state.json"),
                                     str(Path(directory) / "scan.log"))
            monitor.log("test message")
            server = DashboardServer(monitor, "127.0.0.1", 0)
            server.start()
            try:
                port = server.server.server_address[1]
                status = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status"))
                logs = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/logs").read().decode()
                self.assertTrue(status["running"])
                self.assertIn("test message", logs)
            finally:
                server.close()

    def test_resuming_monitor_clears_previous_terminal_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state_path.write_text(json.dumps({
                "running": False,
                "finished_at": "2026-08-25T17:14:21+00:00",
                "error": "Too many open files",
            }), encoding="utf-8")
            monitor = RuntimeMonitor(str(state_path), str(Path(directory) / "scan.log"))
            self.assertTrue(monitor.state["running"])
            self.assertNotIn("finished_at", monitor.state)
            self.assertNotIn("error", monitor.state)

    def test_warc_paths_are_read_from_the_local_manifest_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "CC-TEST.warc-paths.json"
            expected = ["https://data.commoncrawl.org/cc-index/table/part-00000-test.parquet"]
            cache.write_text(json.dumps(expected), encoding="utf-8")
            self.assertEqual(get_warc_parquet_paths("CC-TEST", cache), expected)

    def test_streaming_pipeline_downloads_and_finishes_one_shard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "part-00000-test.parquet"
            con = duckdb.connect()
            con.execute("""CREATE TABLE idx(
              url_host_registered_domain VARCHAR, url_host_name VARCHAR, url VARCHAR,
              url_path VARCHAR, url_query VARCHAR, fetch_status SMALLINT, fetch_time TIMESTAMP,
              content_mime_type VARCHAR, content_languages VARCHAR, warc_filename VARCHAR,
              warc_record_offset BIGINT, warc_record_length BIGINT, subset VARCHAR)""")
            con.executemany("INSERT INTO idx VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [[
                "example.com", "maps.example.com", f"https://maps.example.com/geoserver/wms/{number}",
                f"/geoserver/wms/{number}", "", 200, "2026-08-20", "image/png", "eng",
                "unused.warc.gz", number, 100, "warc",
            ] for number in range(1, 4)])
            con.execute(f"COPY idx TO '{source}' (FORMAT PARQUET)")
            con.close()

            handler = functools.partial(QuietHandler, directory=directory)
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                args = SimpleNamespace(
                    runtime_dir=str(root / "runtime"), output=str(root / "results"),
                    bandwidth_mbit=0, memory="1GB", threads=2,
                    cache_dir=str(root / "warc-cache"), workers=1,
                    max_record_bytes=1_000_000, max_body_bytes=100_000,
                    parse_workers=1, batch_size=2, max_candidates=1,
                    analysis_workers=2,
                    keep_warc_cache=False,
                )
                monitor = RuntimeMonitor(str(root / "status.json"), str(root / "scan.log"))
                url = f"http://127.0.0.1:{httpd.server_address[1]}/{source.name}"
                run_streaming(args, "CC-TEST", [url], monitor, BandwidthLimiter(0))
                self.assertEqual(monitor.state["phase"], "budget_reached")
                args.max_candidates = 0
                run_streaming(args, "CC-TEST", [url], monitor, BandwidthLimiter(0))
            finally:
                httpd.shutdown()
                httpd.server_close()

            outputs = list((root / "results" / "CC-TEST").glob("part-*.parquet"))
            self.assertEqual(len(outputs), 1)
            result_connection = duckdb.connect()
            self.assertEqual(result_connection.execute("SELECT count(*) FROM read_parquet(?)",
                                                       [str(outputs[0])]).fetchone()[0], 3)
            row = result_connection.execute("SELECT evidence_state, notes FROM read_parquet(?)",
                                            [str(outputs[0])]).fetchone()
            self.assertEqual(row[0], "PRODUCT_DETECTED")
            self.assertIn("MIME_FILTERED", row[1])
            self.assertTrue(monitor.state["shards"]["00000"]["stage2_done"])
            self.assertFalse(list((root / "runtime").rglob("*.parquet")))


if __name__ == "__main__":
    unittest.main()
