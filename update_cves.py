#!/usr/bin/env python3
"""Update normalized CVE knowledge from CVE.org, NVD and GHSA."""
import argparse
import json

from src.cve_importer import update_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Update cc-scan CVE knowledge sources")
    parser.add_argument("--rules", default="data/cve_rules.json")
    parser.add_argument("--output", help="Write to another JSON file instead of updating --rules")
    parser.add_argument("--cache-dir", default=".cache/cve")
    parser.add_argument("--max-age-hours", type=int, default=24)
    args = parser.parse_args()
    print(json.dumps(update_file(args.rules, args.cache_dir, args.max_age_hours, args.output), indent=2))


if __name__ == "__main__":
    main()
