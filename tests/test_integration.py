import tempfile
import unittest
from pathlib import Path

try:
    import duckdb
except ImportError:
    duckdb = None

from pipeline_runner import run_stage1, write_parquet
from src.pipeline import analyze_record
from tests.test_pipeline import response


@unittest.skipIf(duckdb is None, "duckdb optional test dependency is not installed")
class ParquetIntegrationTests(unittest.TestCase):
    def test_stage1_to_final_parquet_preserves_query_and_405(self):
        with tempfile.TemporaryDirectory() as directory:
            source = str(Path(directory) / "index.parquet")
            candidates = str(Path(directory) / "candidates.parquet")
            final = str(Path(directory) / "final.parquet")
            con = duckdb.connect()
            con.execute("""CREATE TABLE idx(
              url_host_registered_domain VARCHAR, url_host_name VARCHAR, url VARCHAR,
              url_path VARCHAR, url_query VARCHAR, fetch_status SMALLINT, fetch_time TIMESTAMP,
              content_mime_type VARCHAR, content_languages VARCHAR, warc_filename VARCHAR,
              warc_record_offset BIGINT, warc_record_length BIGINT, subset VARCHAR)""")
            con.executemany("INSERT INTO idx VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
                ("example.com", "app.example.com", "https://app.example.com/api/v1/validate/code",
                 "/api/v1/validate/code", "", 405, "2026-08-20", "application/json", "eng", "x", 1, 2, "warc"),
                ("example.com", "cdn.example.com", "https://cdn.example.com/jquery.min.js?ver=3.4.1",
                 "/jquery.min.js", "ver=3.4.1", 200, "2026-08-20", "application/javascript", "eng", "y", 3, 4, "warc"),
            ])
            con.execute(f"COPY idx TO '{source}' (FORMAT PARQUET)")
            run_stage1(con, [source], candidates)
            cursor = con.execute(f"SELECT * FROM read_parquet('{candidates}') ORDER BY url")
            names = [item[0] for item in cursor.description]
            rows = [dict(zip(names, values)) for values in cursor.fetchall()]
            self.assertEqual(rows[0]["fetch_status"], 405)
            self.assertEqual(rows[1]["normalized_query"], "ver=3.4.1")
            enriched = analyze_record(rows[1], response("/*! jQuery */", content_type="application/javascript"))
            write_parquet(con, enriched, final)
            state, version = con.execute(f"SELECT evidence_state, detected_version FROM read_parquet('{final}')").fetchone()
            self.assertEqual((state, version), ("LIKELY_VULNERABLE", "3.4.1"))

    def test_stage1_routes_extended_product_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            source = str(Path(directory) / "index.parquet")
            candidates = str(Path(directory) / "candidates.parquet")
            con = duckdb.connect()
            con.execute("""CREATE TABLE idx(
              url_host_registered_domain VARCHAR, url_host_name VARCHAR, url VARCHAR,
              url_path VARCHAR, url_query VARCHAR, fetch_status SMALLINT, fetch_time TIMESTAMP,
              content_mime_type VARCHAR, content_languages VARCHAR, warc_filename VARCHAR,
              warc_record_offset BIGINT, warc_record_length BIGINT, subset VARCHAR)""")
            paths = [
                ("/jnlpJars/jenkins-cli.jar", "Jenkins"),
                ("/public/plugins/graph/module.js", "Grafana"),
                ("/wp-content/plugins/wp-automatic/js/main.js", "WordPress Automatic"),
                ("/_layouts/15/start.aspx", "Microsoft SharePoint"),
            ]
            con.executemany("INSERT INTO idx VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
                ("example.com", f"h{number}.example.com", "https://example.com" + path,
                 path, "", 200, "2026-08-20", "text/html", "eng", "x", number, 100, "warc")
                for number, (path, _) in enumerate(paths, 1)
            ])
            con.execute(f"COPY idx TO '{source}' (FORMAT PARQUET)")
            run_stage1(con, [source], candidates)
            actual = dict(con.execute(
                f"SELECT normalized_path, product_hint FROM read_parquet('{candidates}')").fetchall())
            self.assertEqual(actual, {path.lower(): product for path, product in paths})


if __name__ == "__main__":
    unittest.main()
