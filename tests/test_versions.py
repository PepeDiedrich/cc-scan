import unittest

from src.cve_matcher import _in_range
from src.settings import CVE_RULES
from src.version_detector import compare_versions


class VersionComparisonTests(unittest.TestCase):
    def test_numeric_not_lexicographic(self):
        self.assertGreater(compare_versions("9.0.80", "9.0.9"), 0)

    def test_hotfix_order(self):
        self.assertGreater(compare_versions("11.1.2-h3", "11.1.2-h2"), 0)

    def test_geoserver_branch_fix(self):
        rule = next(r for r in CVE_RULES if r["cve_id"] == "CVE-2024-36401")
        self.assertTrue(_in_range("2.25.1", rule))
        self.assertFalse(_in_range("2.24.5", rule))


if __name__ == "__main__":
    unittest.main()
