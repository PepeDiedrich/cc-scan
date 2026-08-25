from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .version_detector import DetectedVersion, compare_versions


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _in_range(version: str, rule: dict[str, Any]) -> bool:
    if rule.get("range_matching_disabled"):
        return False
    branch_fixes = rule.get("fixed_version_by_branch", {})
    if branch_fixes:
        match = re.match(r"(\d+\.\d+)", version)
        fixed = branch_fixes.get(match.group(1)) if match else None
        return bool(fixed and compare_versions(version, fixed) < 0)
    imported_ranges = rule.get("affected_ranges", [])
    if imported_ranges:
        for item in imported_ranges:
            start, end = item.get("start"), item.get("end")
            start_ok = not start or compare_versions(version, start) > 0 or (
                compare_versions(version, start) == 0 and item.get("start_inclusive", True))
            end_ok = not end or compare_versions(version, end) < 0 or (
                compare_versions(version, end) == 0 and item.get("end_inclusive", True))
            if start_ok and end_ok:
                return True
        return False
    start, end = rule.get("affected_version_start"), rule.get("affected_version_end")
    if start:
        cmp = compare_versions(version, start)
        if cmp < 0 or (cmp == 0 and not rule.get("affected_version_start_inclusive", True)):
            return False
    if end:
        cmp = compare_versions(version, end)
        if cmp > 0 or (cmp == 0 and not rule.get("affected_version_end_inclusive", True)):
            return False
    return bool(start or end)


def match_cves(product: str, version: DetectedVersion | None, path: str,
               product_confidence: float, configuration_confidence: float | None = None
               ) -> list[dict[str, Any]]:
    from .settings import CVE_RULES

    matches = []
    for rule in CVE_RULES:
        if rule["product"].lower() != product.lower():
            continue
        protocol = rule.get("required_protocol", "unknown")
        if protocol != "HTTP" or rule.get("passively_detectable") is False:
            continue
        if product_confidence < 0.5:
            # A path hint by itself must never become a CVE candidate.
            continue
        endpoint = rule.get("required_endpoint")
        endpoint_match = not endpoint or bool(re.search(endpoint, path, re.I))
        if not endpoint_match:
            continue
        range_match = bool(version and _in_range(version.normalized_version, rule))
        fixed_exact = bool(version and version.normalized_version in rule.get("fixed_versions", []))
        if fixed_exact:
            continue
        has_usable_range = not rule.get("range_matching_disabled") and bool(
            rule.get("affected_version_start") or rule.get("affected_version_end") or
            rule.get("fixed_version_by_branch") or rule.get("affected_ranges"))
        if version and has_usable_range and not range_match:
            continue
        # Product+endpoint can form a candidate. A version-range match raises it,
        # but remains VERSION_APPEARS_AFFECTED because patches may be backported.
        confidence = 0.42 * product_confidence + 0.18
        if version:
            confidence += 0.25 * version.version_confidence
        if range_match:
            confidence += 0.15
        matches.append({
            **rule, "version_range_matches": range_match,
            "backport_status": "unknown" if range_match else None,
            "version_assessment": "VERSION_APPEARS_AFFECTED" if range_match else "VERSION_UNKNOWN_OR_OUT_OF_RANGE",
            "configuration_confidence": configuration_confidence,
            "cve_match_confidence": round(min(confidence, 0.99), 3),
        })
    return matches
