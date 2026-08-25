from pathlib import Path
from .cve_matcher import load_rules

ROOT = Path(__file__).resolve().parents[1]
CVE_RULES = load_rules(ROOT / "data" / "cve_rules.json")
FINGERPRINT_FILE = ROOT / "data" / "product_fingerprints.json"
PASSIVE_ONLY = True
