import unittest
from pathlib import Path
import tempfile

try:
    import brotli
except ImportError:
    brotli = None

from src.dns_evidence import assess_takeover
from src.pipeline import analyze_record
from src.response_parser import parse_warc_record
from src.soft404_index import Soft404Index
from src.version_detector import detect_version


def response(body: str, status=200, content_type="text/html"):
    raw = ("WARC/1.0\r\nContent-Type: application/http; msgtype=response\r\n\r\n"
           f"HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\n"
           "Server: test\r\nSet-Cookie: SESSION=do-not-store\r\n\r\n" + body).encode()
    return parse_warc_record(raw)


def row(path, product, query="", status=200):
    return {
        "registered_domain": "example.com", "host": "app.example.com",
        "url": "https://app.example.com" + path + (("?" + query) if query else ""),
        "normalized_path": path.lower(), "normalized_query": query.lower(),
        "normalized_url": "https://app.example.com" + path.lower(),
        "fetch_status": status, "fetch_time": "2026-08-20T00:00:00+00:00",
        "content_mime_type": "text/html", "content_languages": "eng",
        "product_hint": product, "observed_signal": "PRODUCT_ENDPOINT_OBSERVED",
        "endpoint_confidence": 0.75, "suggested_validation_tags": "passive",
        "warc_filename": "x", "warc_record_offset": 1, "warc_record_length": 2,
    }


class PipelineTests(unittest.TestCase):
    def test_geoserver_path_without_version_is_not_confirmed(self):
        result = analyze_record(row("/geoserver/wms", "GeoServer"), response("<title>GeoServer</title>"))[0]
        self.assertEqual(result["evidence_state"], "PRODUCT_DETECTED")

    def test_geoserver_affected_version_is_likely(self):
        result = analyze_record(row("/geoserver/wms", "GeoServer"),
                                response("<title>GeoServer</title>GeoServer 2.25.1"))[0]
        self.assertEqual(result["detected_version"], "2.25.1")
        self.assertEqual(result["evidence_state"], "LIKELY_VULNERABLE")
        self.assertIn("backport", result["notes"])

    def test_env_spa_fallback_is_not_secret_leak(self):
        spa = response('<html><div id="root"></div><script src="app.js"></script></html>')
        candidate = row("/.env", "Sensitive file")
        candidate["observed_signal"] = "SECRET_FILE_PATH_OBSERVED"
        result = analyze_record(candidate, spa, [("/", spa)])[0]
        self.assertEqual(result["vulnerability_category"], "SECRET_FILE_PATH_OBSERVED")
        self.assertGreaterEqual(result["spa_fallback_probability"], 0.7)

    def test_soft404_index_crosses_batch_boundaries(self):
        spa = response('<html><div id="root"></div><script src="app.js"></script></html>')
        with tempfile.TemporaryDirectory() as directory, Soft404Index(str(Path(directory) / "index.db")) as index:
            index.add("root", "app.example.com", "/", spa)
            index.add("env", "app.example.com", "/.env", spa)
            index.commit()
            context = index.context("app.example.com", "/.env", spa.normalized_body_hash)
            candidate = row("/.env", "Sensitive file")
            candidate["observed_signal"] = "SECRET_FILE_PATH_OBSERVED"
            result = analyze_record(candidate, spa, soft404_context=context)[0]
            self.assertGreaterEqual(result["spa_fallback_probability"], 0.7)

    def test_env_content_is_observed_without_secret_value(self):
        candidate = row("/.env", "Sensitive file")
        candidate["observed_signal"] = "SECRET_FILE_PATH_OBSERVED"
        result = analyze_record(candidate, response("DATABASE_URL=postgres://user:secret@db/x\n"))[0]
        self.assertEqual(result["vulnerability_category"], "SECRET_CONTENT_OBSERVED")
        self.assertEqual(result["evidence_state"], "CONFIRMED")
        self.assertNotIn("postgres://", result["evidence_json"])
        self.assertIn("DATABASE_URL", result["evidence_json"])

    def test_jquery_version_from_query(self):
        parsed = response("/*! jQuery */", content_type="application/javascript")
        found = detect_version("jQuery", "/jquery.min.js", "ver=3.4.1", parsed)
        self.assertEqual(found.normalized_version, "3.4.1")
        self.assertEqual(found.version_source, "url_query")

        component = row("/jquery.min.js", "jQuery", "ver=3.4.1")
        component["observed_signal"] = "CLIENT_COMPONENT_PATH_OBSERVED"
        result = analyze_record(component, parsed)[0]
        self.assertEqual(result["vulnerability_category"], "VULNERABLE_CLIENT_COMPONENT_PRESENT")
        self.assertEqual(result["evidence_state"], "LIKELY_VULNERABLE")

    def test_405_is_in_stage1_status_set(self):
        sql = Path("sql/01_prefilter.sql").read_text(encoding="utf-8")
        self.assertRegex(sql, r"fetch_status IN \([^)]*405")

    def test_client_library_prefilter_requires_javascript_asset(self):
        sql = Path("sql/01_prefilter.sql").read_text(encoding="utf-8")
        self.assertIn("concrete JavaScript asset path", sql)
        self.assertRegex(sql, r"AND NOT regexp_matches\(normalized_path")
        self.assertIn("observed_signal <> 'CLIENT_COMPONENT_PATH_OBSERVED'", sql)

    def test_direct_provider_404_is_not_takeover(self):
        self.assertIsNone(assess_takeover("random-project.github.io", "github.io", [], True, False))

    def test_custom_domain_with_dns_evidence_is_hint(self):
        finding = assess_takeover("app.example.com", "example.com",
                                  ["unclaimed.github.io"], True, False)
        self.assertEqual(finding["signal"], "TAKEOVER_HINT")

    def test_parser_retains_safe_header_and_only_cookie_name(self):
        parsed = response("ok")
        self.assertEqual(parsed.headers["server"], "test")
        self.assertEqual(parsed.cookies, ["SESSION"])

    @unittest.skipIf(brotli is None, "brotli test dependency is not installed")
    def test_brotli_response_body_is_decoded(self):
        body = b"<title>GeoServer</title>GeoServer 2.25.1"
        raw = (b"WARC/1.0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
               b"Content-Encoding: br\r\n\r\n" + brotli.compress(body))
        parsed = parse_warc_record(raw)
        self.assertIn("GeoServer 2.25.1", parsed.text)

    def test_jolokia_does_not_become_openwire_cve(self):
        result = analyze_record(row("/jolokia/", "Jolokia/ActiveMQ"),
                                response("<title>Jolokia</title>ActiveMQ"))[0]
        self.assertIsNone(result["cve_id"])
        self.assertEqual(result["required_protocol"], "OpenWire")
        self.assertEqual(result["evidence_state"], "PRODUCT_DETECTED")


if __name__ == "__main__":
    unittest.main()
