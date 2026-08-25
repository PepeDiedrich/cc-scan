import json
import unittest
from pathlib import Path

from src.pipeline import analyze_record
from tests.test_pipeline import response, row


REQUESTED_IDS = set("""CVE-2024-23897 CVE-2023-7028 CVE-2022-26134 CVE-2023-42793
CVE-2024-4577 CVE-2022-22965 CVE-2020-5405 CVE-2019-3799 CVE-2024-38856
CVE-2023-31418 CVE-2021-29441 CVE-2021-43798 CVE-2021-27905 CVE-2024-24919
CVE-2023-27997 CVE-2023-38035 CVE-2024-27956 CVE-2023-38000 CVE-2024-27954
CVE-2023-43660 CVE-2023-5631 CVE-2023-29489 CVE-2024-37085 CVE-2023-40044
CVE-2022-22954 CVE-2023-3519 CVE-2021-26084 CVE-2023-50164 CVE-2024-27348
CVE-2024-36599 CVE-2024-23334 CVE-2023-46589 CVE-2021-44228 CVE-2024-34102
CVE-2024-20767 CVE-2023-23752 CVE-2022-24706 CVE-2023-24489 CVE-2024-1709
CVE-2024-20353 CVE-2023-38606 CVE-2022-41082 CVE-2023-29357 CVE-2021-23358
CVE-2020-7788 CVE-2021-3749 CVE-2022-25883""".split())


class ExtendedCveTests(unittest.TestCase):
    def test_every_requested_id_has_an_auditable_rule(self):
        rules = json.loads(Path("data/cve_rules.json").read_text(encoding="utf-8"))
        self.assertFalse(REQUESTED_IDS - {rule["cve_id"] for rule in rules})
        by_id = {rule["cve_id"]: rule for rule in rules}
        self.assertEqual(by_id["CVE-2023-31418"]["product"], "Elasticsearch")
        self.assertEqual(by_id["CVE-2020-7788"]["product"], "ini")
        self.assertEqual(by_id["CVE-2023-38606"]["product"], "Apple operating systems")

    def test_jenkins_affected_and_fixed_versions(self):
        affected = analyze_record(row("/jenkins/", "Jenkins"),
                                  response("<title>Dashboard [Jenkins]</title>Jenkins ver. 2.441"))
        finding = next(item for item in affected if item["cve_id"] == "CVE-2024-23897")
        self.assertEqual(finding["evidence_state"], "LIKELY_VULNERABLE")
        self.assertEqual(finding["cve_cvss_score"], 9.8)

        fixed = analyze_record(row("/jenkins/", "Jenkins"),
                               response("<title>Dashboard [Jenkins]</title>Jenkins ver. 2.442"))
        self.assertNotIn("CVE-2024-23897", {item["cve_id"] for item in fixed})

    def test_gitlab_branch_range(self):
        body = '<meta content="GitLab Community Edition"> GitLab CE 16.7.1'
        results = analyze_record(row("/users/password", "GitLab"), response(body))
        finding = next(item for item in results if item["cve_id"] == "CVE-2023-7028")
        self.assertEqual(finding["evidence_state"], "LIKELY_VULNERABLE")

    def test_confluence_and_teamcity_ranges(self):
        confluence = response('<meta name="ajs-version-number" content="7.18.0">Atlassian Confluence')
        confluence_results = analyze_record(row("/confluence/", "Atlassian Confluence"), confluence)
        self.assertIn("CVE-2022-26134", {item["cve_id"] for item in confluence_results})

        teamcity = response("TeamCity Version 2023.05.3 teamcity-server")
        teamcity_results = analyze_record(row("/login.html", "JetBrains TeamCity"), teamcity)
        finding = next(item for item in teamcity_results if item["cve_id"] == "CVE-2023-42793")
        self.assertEqual(finding["evidence_state"], "LIKELY_VULNERABLE")

    def test_grafana_elasticsearch_and_wordpress_rules(self):
        grafana_results = analyze_record(row("/public/plugins/graph/", "Grafana"),
                                         response("<title>Grafana</title>Grafana v8.2.6"))
        self.assertIn("CVE-2021-43798", {item["cve_id"] for item in grafana_results})

        elastic = response('{"cluster_name":"prod","version":{"number":"8.8.1"},'
                           '"tagline":"You Know, for Search"}', content_type="application/json")
        elastic_results = analyze_record(row("/_cluster/health", "Elasticsearch"), elastic)
        self.assertIn("CVE-2023-31418", {item["cve_id"] for item in elastic_results})

        wordpress = response('<meta name="generator" content="WordPress 6.3.1"> wp-content')
        wordpress_results = analyze_record(row("/wp-content/themes/x/style.css", "WordPress"), wordpress)
        self.assertIn("CVE-2023-38000", {item["cve_id"] for item in wordpress_results})

    def test_non_http_rules_never_become_cve_candidates(self):
        warpgate = analyze_record(row("/warpgate/", "Warpgate"), response("Warpgate 0.8.0"))
        log4j = analyze_record(row("/lib/log4j-core-2.14.1.jar", "Apache Log4j"),
                              response("org.apache.logging.log4j log4j-core 2.14.1"))
        self.assertNotIn("CVE-2023-43660", {item["cve_id"] for item in warpgate})
        self.assertNotIn("CVE-2021-44228", {item["cve_id"] for item in log4j})

    def test_prefilter_routes_new_product_families(self):
        sql = Path("sql/01_prefilter.sql").read_text(encoding="utf-8")
        for marker in ("jenkins-cli", "wp-automatic", "public/plugins", "clients/mycrl",
                       "setupwizard", "_layouts/15", "underscore", "axios"):
            self.assertIn(marker, sql.lower())


if __name__ == "__main__":
    unittest.main()
