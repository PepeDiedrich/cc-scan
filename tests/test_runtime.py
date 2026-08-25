import functools
import io
import json
import threading
import tempfile
import unittest
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import duckdb

from pipeline_runner import run_streaming
from src.runtime import BandwidthLimiter, DashboardServer, RuntimeMonitor, copy_limited


class RecordingLimiter:
    def __init__(self):
        self.amounts = []

    def acquire(self, amount):
        self.amounts.append(amount)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return


class RuntimeTests(unittest.TestCase):
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
                "example.com", "cdn.example.com", f"https://cdn.example.com/jquery-{number}.js",
                f"/jquery-{number}.js", "", 200, "2026-08-20", "image/png", "eng",
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
