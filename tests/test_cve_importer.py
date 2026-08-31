import unittest
from unittest.mock import patch

from src.cve_importer import (CVEImporter, has_curated_range, ranges_from_cve_org,
                              ranges_from_ghsa, ranges_from_nvd)


RULE = {"vendor": "Acme", "product": "Widget", "cve_id": "CVE-2099-0001"}


class CVEImporterTests(unittest.TestCase):
    @patch("src.cve_importer._request")
    def test_github_budget_reserves_one_request(self, request):
        request.return_value = (b'{"resources":{"core":{"remaining":3}}}', "application/json")
        importer = CVEImporter()
        self.assertEqual(importer._github_budget({}, 10), 2)

    @patch("src.cve_importer._request", side_effect=OSError("offline"))
    @patch.dict("os.environ", {}, clear=True)
    def test_github_budget_fails_closed_without_token(self, _request):
        importer = CVEImporter()
        self.assertEqual(importer._github_budget({}, 10), 0)
        self.assertEqual(len(importer.errors), 1)

    def test_nvd_cpe_range_is_normalized(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0"
        }]}]}]}
        self.assertEqual(ranges_from_nvd(RULE, cve)[0]["end_inclusive"], False)

    def test_cve_org_cna_range_is_normalized(self):
        record = {"containers": {"cna": {"affected": [{
            "vendor": "Acme", "product": "Widget", "versions": [{
                "status": "affected", "version": "1.0.0", "lessThan": "2.0.0"
            }]
        }]}}}
        result = ranges_from_cve_org(RULE, record)[0]
        self.assertEqual((result["start"], result["end"], result["source"]),
                         ("1.0.0", "2.0.0", "cve.org"))

    def test_ghsa_semver_range_is_normalized(self):
        advisories = [{"vulnerabilities": [{"package": {"name": "widget"},
                                             "vulnerable_version_range": ">= 1.0.0, < 2.0.0"}]}]
        result = ranges_from_ghsa(RULE, advisories)[0]
        self.assertEqual((result["start_inclusive"], result["end_inclusive"]), (True, False))

    def test_curated_affected_ranges_are_protected_by_updater(self):
        self.assertTrue(has_curated_range({"affected_ranges": [{"end": "2.0"}]}))
        self.assertTrue(has_curated_range({"range_matching_disabled": True}))
        self.assertFalse(has_curated_range({"fixed_versions": ["2.0"]}))


if __name__ == "__main__":
    unittest.main()
