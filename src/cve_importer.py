from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
GHSA_URL = "https://api.github.com/advisories"
GITHUB_RATE_URL = "https://api.github.com/rate_limit"
SOURCE_PRIORITY = {"vendor": 100, "cve.org": 90, "ghsa": 80, "nvd": 70}


def _request(url: str, headers: dict[str, str] | None = None, timeout: int = 60,
             attempts: int = 3) -> tuple[bytes, str]:
    base_headers = {"User-Agent": "cc-scan/3.0 CVE knowledge updater", "Accept": "application/json"}
    base_headers.update(headers or {})
    last_error = None
    attempts = max(1, attempts)
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=base_headers), timeout=timeout) as response:
                return response.read(), response.headers.get("Content-Type", "")
        except OSError as exc:
            last_error = exc
            if attempt < attempts - 1:
                delay = 1.0 * (2 ** attempt)
                if isinstance(exc, urllib.error.HTTPError) and exc.code in (403, 429):
                    retry_after = exc.headers.get("Retry-After")
                    reset = exc.headers.get("X-RateLimit-Reset")
                    try:
                        delay = max(delay, float(retry_after)) if retry_after else delay
                    except ValueError:
                        pass
                    try:
                        delay = max(delay, float(reset) - time.time()) if reset else delay
                    except ValueError:
                        pass
                    # Do not stall scan startup for a remote hourly quota window.
                    if delay > 30:
                        break
                time.sleep(min(30.0, max(0.0, delay)))
    raise OSError(f"source request failed: {url}: {last_error}")


def _cache_read(path: Path, max_age_hours: int) -> Any | None:
    if path.exists() and time.time() - path.stat().st_mtime <= max_age_hours * 3600:
        return json.loads(path.read_text(encoding="utf-8"))
    return None


def _cache_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _product_matches(rule: dict[str, Any], vendor: str, product: str) -> bool:
    candidates = [_compact(rule.get("product", ""))]
    candidates.extend(_compact(item) for item in rule.get("product_aliases", []))
    observed = _compact(product)
    product_match = any(len(item) >= 4 and (item in observed or observed in item) for item in candidates)
    rule_vendor, observed_vendor = _compact(rule.get("vendor", "")), _compact(vendor)
    vendor_match = not rule_vendor or not observed_vendor or rule_vendor in observed_vendor or observed_vendor in rule_vendor
    return product_match and vendor_match


def _range(start=None, start_inclusive=True, end=None, end_inclusive=True,
           source="unknown", raw=None) -> dict[str, Any]:
    return {"start": start, "start_inclusive": bool(start_inclusive), "end": end,
            "end_inclusive": bool(end_inclusive), "source": source,
            **({"raw": raw} if raw else {})}


def _walk_cpe_matches(value: Any):
    if isinstance(value, dict):
        for match in value.get("cpeMatch", []):
            yield match
        for child in value.values():
            yield from _walk_cpe_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_cpe_matches(child)


def ranges_from_nvd(rule: dict[str, Any], cve: dict[str, Any]) -> list[dict[str, Any]]:
    ranges = []
    for match in _walk_cpe_matches(cve.get("configurations", [])):
        if not match.get("vulnerable"):
            continue
        parts = match.get("criteria", "").split(":")
        if len(parts) < 6 or not _product_matches(rule, urllib.parse.unquote(parts[3]), urllib.parse.unquote(parts[4])):
            continue
        start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
        end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
        if not start and not end and parts[5] not in ("*", "-"):
            start = end = urllib.parse.unquote(parts[5])
        if start or end:
            ranges.append(_range(start, "versionStartExcluding" not in match,
                                 end, "versionEndExcluding" not in match, "nvd"))
    return ranges


def ranges_from_cve_org(rule: dict[str, Any], record: dict[str, Any], source: str = "cve.org") -> list[dict[str, Any]]:
    ranges = []
    for affected in record.get("containers", {}).get("cna", {}).get("affected", []):
        if not _product_matches(rule, affected.get("vendor", ""), affected.get("product", "")):
            continue
        for version in affected.get("versions", []):
            if version.get("status") != "affected" or version.get("changes"):
                continue
            start = version.get("version")
            end, inclusive = version.get("lessThan"), False
            if version.get("lessThanOrEqual"):
                end, inclusive = version["lessThanOrEqual"], True
            if start in ("*", "n/a", "N/A"):
                start = None
            if end in ("*", "n/a", "N/A"):
                end = None
            if start and not re.search(r"\d", start):
                start = None
            if end and not re.search(r"\d", end):
                end = None
            if start or end:
                ranges.append(_range(start, True, end or (start if not end else None),
                                     inclusive if end else True, source))
    return ranges


def _constraint_ranges(expression: str) -> list[dict[str, Any]]:
    output = []
    for alternative in expression.split("||"):
        start = end = None
        start_inclusive = end_inclusive = True
        for operator, version in re.findall(r"(>=|>|<=|<|=)?\s*v?(\d+(?:\.\d+)+(?:[-+][\w.-]+)?)", alternative):
            if operator in (">", ">="):
                start, start_inclusive = version, operator == ">="
            elif operator in ("<", "<="):
                end, end_inclusive = version, operator == "<="
            elif operator in ("", "="):
                start = end = version
        if start or end:
            output.append(_range(start, start_inclusive, end, end_inclusive, "ghsa", raw=alternative.strip()))
    return output


def ranges_from_ghsa(rule: dict[str, Any], advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranges = []
    for advisory in advisories:
        for vulnerability in advisory.get("vulnerabilities", []):
            package = vulnerability.get("package", {}).get("name", "")
            if _product_matches(rule, "", package):
                ranges.extend(_constraint_ranges(vulnerability.get("vulnerable_version_range", "")))
    return ranges


def _deduplicate_ranges(ranges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {}
    for item in sorted(ranges, key=lambda value: SOURCE_PRIORITY.get(value["source"], 0), reverse=True):
        key = (item.get("start"), item.get("start_inclusive"), item.get("end"), item.get("end_inclusive"))
        unique.setdefault(key, item)
    return list(unique.values())


def has_curated_range(rule: dict[str, Any]) -> bool:
    return bool(rule.get("affected_version_start") or rule.get("affected_version_end") or
                rule.get("fixed_version_by_branch") or rule.get("affected_ranges") or
                rule.get("range_matching_disabled"))


class CVEImporter:
    def __init__(self, cache_dir: str = ".cache/cve", max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.max_age_hours = max_age_hours
        self.errors: list[str] = []
        self.source_skipped_count = 0

    def _github_budget(self, headers: dict[str, str], wanted: int) -> int:
        """Preflight GitHub's primary quota so an update never starts with 403 bursts."""
        if wanted <= 0:
            return 0
        try:
            raw, _ = _request(GITHUB_RATE_URL, headers, attempts=1)
            core = json.loads(raw).get("resources", {}).get("core", {})
            # Keep one request in reserve for small quota races with other processes.
            return min(wanted, max(0, int(core.get("remaining", 0)) - 1))
        except (OSError, ValueError, TypeError) as exc:
            self.errors.append(f"ghsa:rate-check:{exc}")
            # A configured token has ample quota in normal operation. Without one,
            # failing closed prevents the updater from blindly exhausting 60 req/h.
            return wanted if os.environ.get("GITHUB_TOKEN") else 0

    def _json_source(self, source: str, cve_id: str, url: str,
                     headers: dict[str, str] | None = None, timeout: int = 30,
                     attempts: int = 2) -> Any | None:
        path = self.cache_dir / source / f"{cve_id}.json"
        cached = _cache_read(path, self.max_age_hours)
        if cached is not None:
            return cached
        try:
            raw, _ = _request(url, headers, timeout=timeout, attempts=attempts)
            value = json.loads(raw)
            _cache_write(path, value)
            return value
        except (OSError, ValueError) as exc:
            self.errors.append(f"{source}:{cve_id}:{exc}")
            return None

    def _nvd(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        results = {}
        missing = []
        for cve_id in cve_ids:
            cached = _cache_read(self.cache_dir / "nvd" / f"{cve_id}.json", self.max_age_hours)
            if cached is None:
                missing.append(cve_id)
            else:
                results[cve_id] = cached
        headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
        for start in range(0, len(missing), 100):
            group = missing[start:start + 100]
            try:
                query = urllib.parse.urlencode({"cveIds": ",".join(group)})
                raw, _ = _request(f"{NVD_URL}?{query}", headers, timeout=30, attempts=2)
                payload = json.loads(raw)
                for wrapper in payload.get("vulnerabilities", []):
                    cve = wrapper.get("cve", {})
                    cve_id = cve.get("id")
                    if cve_id:
                        results[cve_id] = cve
                        _cache_write(self.cache_dir / "nvd" / f"{cve_id}.json", cve)
            except (OSError, ValueError) as exc:
                self.errors.append(f"nvd:{','.join(group)}:{exc}")
        return results

    def _vendor_source(self, rule: dict[str, Any]) -> dict[str, Any] | None:
        url = rule.get("vendor_advisory_url") or rule.get("vendor_csaf_url")
        if not url:
            return None
        cve_id = rule["cve_id"]
        path = self.cache_dir / "vendor" / f"{cve_id}.json"
        cached = _cache_read(path, self.max_age_hours)
        if cached is not None:
            return cached
        try:
            raw, content_type = _request(
                url, {"Accept": "application/json, text/html;q=0.9"}, timeout=20, attempts=1)
            metadata: dict[str, Any] = {"url": url, "content_type": content_type,
                                        "sha256": hashlib.sha256(raw).hexdigest()}
            if "json" in content_type.lower() or raw.lstrip().startswith((b"{", b"[")):
                metadata["record"] = json.loads(raw)
            _cache_write(path, metadata)
            return metadata
        except (OSError, ValueError) as exc:
            self.errors.append(f"vendor:{cve_id}:{exc}")
            return None

    def update(self, rules: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
        cve_ids = sorted({rule["cve_id"] for rule in rules})
        nvd = self._nvd(cve_ids)
        github_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if os.environ.get("GITHUB_TOKEN"):
            github_headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
        fetched: dict[tuple[str, str], Any] = {}

        missing_ghsa = []
        for cve_id in cve_ids:
            cached = _cache_read(self.cache_dir / "ghsa" / f"{cve_id}.json", self.max_age_hours)
            if cached is None:
                missing_ghsa.append(cve_id)
            else:
                fetched[("ghsa", cve_id)] = cached
        # The anonymous GitHub quota (60/hour per public IP) is smaller than
        # this rule set and is commonly already shared by other processes.
        # Cached GHSA data remains usable; fresh API calls require a token.
        github_budget = (self._github_budget(github_headers, len(missing_ghsa))
                         if os.environ.get("GITHUB_TOKEN") else 0)
        allowed_ghsa = missing_ghsa[:github_budget]
        self.source_skipped_count += len(missing_ghsa) - len(allowed_ghsa)

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {}
            for cve_id in cve_ids:
                futures[pool.submit(self._json_source, "cve.org", cve_id,
                                    CVE_URL.format(cve_id=cve_id))] = ("cve.org", cve_id)
            for rule in rules:
                if rule.get("vendor_advisory_url") or rule.get("vendor_csaf_url"):
                    futures[pool.submit(self._vendor_source, rule)] = ("vendor", rule["cve_id"])
            for future in as_completed(futures):
                fetched[futures[future]] = future.result()

        # Two concurrent GitHub requests avoid the old six-request startup burst
        # while keeping a cold knowledge refresh reasonably quick.
        with ThreadPoolExecutor(max_workers=2) as pool:
            ghsa_futures = {}
            for cve_id in allowed_ghsa:
                url = GHSA_URL + "?" + urllib.parse.urlencode({"cve_id": cve_id, "per_page": 100})
                future = pool.submit(self._json_source, "ghsa", cve_id, url, github_headers)
                ghsa_futures[future] = cve_id
            for future in as_completed(ghsa_futures):
                cve_id = ghsa_futures[future]
                fetched[("ghsa", cve_id)] = future.result()

        now = datetime.now(timezone.utc).isoformat()
        imported_range_count = 0
        for rule in rules:
            cve_id = rule["cve_id"]
            cve_record = fetched.get(("cve.org", cve_id)) or {}
            advisories = fetched.get(("ghsa", cve_id)) or []
            vendor = fetched.get(("vendor", cve_id)) or {}
            all_ranges = _deduplicate_ranges(
                ranges_from_cve_org(rule, vendor.get("record", {}), "vendor") +
                ranges_from_cve_org(rule, cve_record) +
                ranges_from_ghsa(rule, advisories) +
                ranges_from_nvd(rule, nvd.get(cve_id, {})))
            best_priority = max((SOURCE_PRIORITY.get(item["source"], 0) for item in all_ranges), default=0)
            ranges = [item for item in all_ranges if SOURCE_PRIORITY.get(item["source"], 0) == best_priority]
            if ranges and not has_curated_range(rule):
                rule["affected_ranges"] = ranges
                imported_range_count += len(ranges)
            rule["knowledge_sources"] = {
                "updated_at": now,
                "priority": ["vendor", "cve.org", "ghsa", "nvd"],
                "cve_org": bool(cve_record), "nvd": cve_id in nvd,
                "cisa_kev": bool(nvd.get(cve_id, {}).get("cisaExploitAdd")),
                "ghsa_ids": [item.get("ghsa_id") for item in advisories if item.get("ghsa_id")],
                "vendor_advisory_url": rule.get("vendor_advisory_url"),
                "vendor_fetched": bool(vendor),
                "available_range_sources": sorted({item["source"] for item in all_ranges},
                                                   key=lambda item: SOURCE_PRIORITY.get(item, 0), reverse=True),
            }
        return rules, {"rule_count": len(rules), "imported_range_count": imported_range_count,
                       "source_error_count": len(self.errors),
                       "source_skipped_count": self.source_skipped_count}


def update_file(path: str, cache_dir: str = ".cache/cve", max_age_hours: int = 24,
                output: str | None = None) -> dict[str, Any]:
    source = Path(path)
    rules = json.loads(source.read_text(encoding="utf-8"))
    importer = CVEImporter(cache_dir, max_age_hours)
    updated, metrics = importer.update(rules)
    destination = Path(output) if output else source
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, destination)
    return {**metrics, "output": str(destination), "errors": importer.errors}
