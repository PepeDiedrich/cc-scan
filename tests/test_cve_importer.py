import unittest

from src.cve_importer import ranges_from_cve_org, ranges_from_ghsa, ranges_from_nvd


RULE = {"vendor": "Acme", "product": "Widget", "cve_id": "CVE-2099-0001"}


class CVEImporterTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
