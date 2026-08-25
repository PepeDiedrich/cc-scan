from __future__ import annotations

import json
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .confidence import evidence_state, freshness, overall_confidence
from .cve_matcher import match_cves
from .fingerprint import detect_product, detect_secrets, load_fingerprints
from .response_parser import ParsedResponse, parse_warc_record
from .settings import CVE_RULES, FINGERPRINT_FILE
from .soft404 import probabilities
from .soft404_index import Soft404Index
from .version_detector import detect_version
from .warc_fetcher import WarcFetcher


SAFE_HEADERS = ("server", "x-powered-by", "via", "location", "www-authenticate",
                "content-type", "content-length", "x-grafana-version", "x-jenkins")
PUBLIC_CODE_HOST = re.compile(
    r"(?:github(?:usercontent)?\.com|gitlab\.com|bitbucket\.org|googlesource\.com|"
    r"sourceforge\.net|gitee\.com|codeberg\.org)$", re.I)
SENSITIVE_QUERY = re.compile(r"(?i)((?:token|key|secret|password|passwd|signature|auth|session)[^=&]*=)[^&]*")


def analyze_record(row: dict[str, Any], response: ParsedResponse,
                   peers: list[tuple[str, ParsedResponse]] | None = None,
                   fingerprints: dict | None = None,
                   soft404_context: dict[str, int | bool] | None = None) -> list[dict[str, Any]]:
    fingerprints = fingerprints or load_fingerprints(FINGERPRINT_FILE)
    product, product_confidence, product_evidence = detect_product(row, response, fingerprints)
    version = detect_version(product, row.get("normalized_path", ""), row.get("normalized_query", ""), response)
    probs = probabilities(response, row.get("normalized_path", ""), peers, soft404_context)
    secret_findings = detect_secrets(response.text)
    false_document = max(probs["soft_404_probability"], probs["spa_fallback_probability"],
                         probs["generic_waf_probability"], probs["cdn_error_probability"],
                         probs["generic_login_probability"])
    public_source = bool(PUBLIC_CODE_HOST.search(row.get("host", "")))
    secret_content = bool(secret_findings) and false_document < 0.7 and not public_source
    config_confidence = None
    if product == "PAN-OS" and re_search_globalprotect(response):
        config_confidence = 0.65
    cves = match_cves(product, version, row.get("normalized_path", ""),
                      product_confidence, config_confidence)
    age_days, fresh_score = freshness(row.get("fetch_time"))
    response_confidence = round(max(0.1, 1.0 - false_document * 0.8), 3)
    if response.artifacts.get("content_decoding_error"):
        response_confidence = min(response_confidence, 0.25)
    base_evidence = product_evidence + [{
        "type": "http_status", "value": response.status or row.get("fetch_status"), "weight": 0.1
    }]
    if version:
        base_evidence.append({"type": "version_string", "value": version.raw_version,
                              "source": version.version_source, "weight": version.version_confidence})
    if secret_findings:
        base_evidence.append({"type": "secret_detection", "value": secret_findings,
                              "weight": 0.9 if secret_content else 0.1})
    headers = {key: SENSITIVE_QUERY.sub(r"\1<redacted>", response.headers[key][:1000])
               for key in SAFE_HEADERS if key in response.headers}
    base_evidence.extend({"type": "cookie_name", "value": name, "weight": 0.15}
                         for name in response.cookies)

    items = cves or [None]
    related_rule = next((rule for rule in CVE_RULES
                         if rule["product"].lower() == product.lower()), None)
    results = []
    for cve in items:
        category = row.get("observed_signal", "PRODUCT_ENDPOINT_OBSERVED")
        notes = []
        if category == "SECRET_FILE_PATH_OBSERVED":
            category = "SECRET_CONTENT_OBSERVED" if secret_content else "SECRET_FILE_PATH_OBSERVED"
            if not secret_content:
                notes.append("No secret content accepted; response is empty, generic, soft-404, or SPA-like.")
            if public_source:
                category = "PUBLIC_SOURCE_ARTIFACT"
                notes.append("Code-hosting context retained for recall but not classified as an operator secret leak.")
        elif product in ("jQuery", "PDF.js") and version:
            category = "VULNERABLE_CLIENT_COMPONENT_PRESENT" if cve and cve.get("version_range_matches") else "CLIENT_COMPONENT_PRESENT"
            notes.append("Component presence does not prove vulnerable application behavior is reachable.")
        if cve and cve.get("version_range_matches"):
            notes.append("VERSION_APPEARS_AFFECTED; backport/patch status unknown.")
        if not cve and related_rule and related_rule.get("required_protocol") != "HTTP":
            notes.append(f"Related CVE requires {related_rule['required_protocol']}; Common Crawl HTTP cannot observe it.")
        cve_conf = cve.get("cve_match_confidence") if cve else None
        state = evidence_state(product_confidence, cve)
        # Content exposure is directly present in the archive, but CONFIRMED is
        # reserved for the observed exposure, never an inferred CVE.
        if secret_content:
            state = "CONFIRMED"
        overall = overall_confidence(
            product=product_confidence, version=version.version_confidence if version else None,
            endpoint=row.get("endpoint_confidence"), configuration=config_confidence,
            cve_match=cve_conf, response=response_confidence, freshness_score=fresh_score)
        evidence = {
            "product": product, "evidence": base_evidence, "headers": headers,
            "title": response.title, "meta_generator": response.meta_generator,
            "javascript": response.artifacts, "secrets": secret_findings,
            "response_truncated": response.truncated,
        }
        results.append({
            "registered_domain": row.get("registered_domain"), "host": row.get("host"),
            "url": row.get("url"), "normalized_path": row.get("normalized_path"),
            "normalized_query": row.get("normalized_query"), "normalized_url": row.get("normalized_url"),
            "fetch_status": row.get("fetch_status"), "fetch_time": _json_time(row.get("fetch_time")),
            "content_mime_type": row.get("content_mime_type"), "content_languages": row.get("content_languages"),
            "product": product, "product_confidence": product_confidence,
            "detected_version": version.normalized_version if version else None,
            "version_source": version.version_source if version else None,
            "version_confidence": version.version_confidence if version else None,
            "cve_id": cve.get("cve_id") if cve else None,
            "cve_match_confidence": cve_conf,
            "required_protocol": (cve or related_rule or {}).get("required_protocol"),
            "required_configuration": (cve or related_rule or {}).get("required_configuration"),
            "configuration_confidence": config_confidence,
            "vulnerability_category": category, "evidence_state": state,
            "overall_confidence": overall, "response_confidence": response_confidence,
            "freshness_score": fresh_score, "observed_at": _json_time(row.get("fetch_time")),
            "crawl_age_days": age_days, "response_sha256": response.response_sha256,
            "normalized_body_hash": response.normalized_body_hash, "body_length": response.body_length,
            **probs, "warc_filename": row.get("warc_filename"),
            "warc_record_offset": row.get("warc_record_offset"),
            "warc_record_length": row.get("warc_record_length"),
            "suggested_validation_tags": row.get("suggested_validation_tags"),
            "evidence_json": json.dumps(evidence, ensure_ascii=False, default=str),
            "notes": " ".join(notes + ([cve.get("notes", "")] if cve else [])).strip(),
        })
    return results


def re_search_globalprotect(response: ParsedResponse) -> bool:
    text = f"{response.title or ''} {response.text[:200000]}"
    return "globalprotect" in text.lower()


def _json_time(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def fallback_result(row: dict[str, Any], reason: str) -> dict[str, Any]:
    age_days, fresh_score = freshness(row.get("fetch_time"))
    product = row.get("product_hint") or "Unknown"
    product_confidence = 0.3 if product not in ("Unknown", "Generic security endpoint") else 0.2
    return {
        "registered_domain": row.get("registered_domain"), "host": row.get("host"), "url": row.get("url"),
        "normalized_path": row.get("normalized_path"), "normalized_query": row.get("normalized_query"),
        "normalized_url": row.get("normalized_url"), "fetch_status": row.get("fetch_status"),
        "fetch_time": _json_time(row.get("fetch_time")), "content_mime_type": row.get("content_mime_type"),
        "content_languages": row.get("content_languages"), "product": product,
        "product_confidence": product_confidence, "detected_version": None, "version_source": None,
        "version_confidence": None, "cve_id": None, "cve_match_confidence": None,
        "required_protocol": None, "required_configuration": None, "configuration_confidence": None,
        "vulnerability_category": row.get("observed_signal", "PRODUCT_ENDPOINT_OBSERVED"),
        "evidence_state": "PRODUCT_DETECTED", "overall_confidence": overall_confidence(
            product=product_confidence, version=None, endpoint=row.get("endpoint_confidence"),
            configuration=None, cve_match=None, response=0.0, freshness_score=fresh_score),
        "response_confidence": 0.0, "freshness_score": fresh_score,
        "observed_at": _json_time(row.get("fetch_time")), "crawl_age_days": age_days,
        "response_sha256": None, "normalized_body_hash": None, "body_length": None,
        "soft_404_probability": None, "spa_fallback_probability": None,
        "generic_waf_probability": None, "cdn_error_probability": None,
        "generic_login_probability": None, "warc_filename": row.get("warc_filename"),
        "warc_record_offset": row.get("warc_record_offset"), "warc_record_length": row.get("warc_record_length"),
        "suggested_validation_tags": row.get("suggested_validation_tags"),
        "evidence_json": json.dumps({"product": product, "evidence": [{"type": "url_path",
            "value": row.get("normalized_path"), "weight": product_confidence}], "response_unavailable": reason}),
        "notes": f"Response analysis unavailable: {reason}; URL evidence was not promoted to a CVE.",
    }


def enrich_rows(rows: list[dict[str, Any]], fetcher: WarcFetcher,
                max_body_bytes: int = 2_000_000,
                soft404_index: Soft404Index | None = None,
                parse_workers: int = 1) -> tuple[list[dict], dict[str, int]]:
    binary_prefixes = ("image/", "audio/", "video/", "font/")
    selected, skipped = [], []
    for row in rows:
        (skipped if str(row.get("content_mime_type") or "").lower().startswith(binary_prefixes)
         else selected).append(row)
    records = [(r["warc_filename"], int(r["warc_record_offset"]), int(r["warc_record_length"])) for r in selected]
    fetched = fetcher.fetch_many(records)
    parsed_by_key, failures = _parse_fetched(fetched, max_body_bytes, parse_workers)
    host_peers: dict[str, list[tuple[str, ParsedResponse]]] = defaultdict(list)
    for row in selected:
        key = (row["warc_filename"], int(row["warc_record_offset"]), int(row["warc_record_length"]))
        if key in parsed_by_key:
            host_peers[row["host"]].append((row["normalized_path"], parsed_by_key[key]))
    output = [fallback_result(row, "MIME_FILTERED") for row in skipped]
    definitions = load_fingerprints(FINGERPRINT_FILE)
    for row in selected:
        key = (row["warc_filename"], int(row["warc_record_offset"]), int(row["warc_record_length"]))
        response = parsed_by_key.get(key)
        if response:
            context = soft404_index.context(row["host"], row["normalized_path"],
                                            response.normalized_body_hash) if soft404_index else None
            output.extend(analyze_record(row, response, host_peers[row["host"]], definitions,
                                         soft404_context=context))
        else:
            output.append(fallback_result(row, "WARC_FETCH_FAILED"))
    return output, {"candidate_count": len(rows), "mime_skipped_count": len(rows) - len(selected),
                    "warc_record_count": len(fetched),
                    "warc_failure_count": failures, "result_count": len(output)}


def index_soft404_rows(rows: list[dict[str, Any]], fetcher: WarcFetcher,
                       index: Soft404Index, max_body_bytes: int = 2_000_000,
                       parse_workers: int = 1) -> dict[str, int]:
    binary_prefixes = ("image/", "audio/", "video/", "font/")
    selected = [row for row in rows if not str(row.get("content_mime_type") or "").lower().startswith(binary_prefixes)]
    records = [(r["warc_filename"], int(r["warc_record_offset"]), int(r["warc_record_length"])) for r in selected]
    fetched = fetcher.fetch_many(records)
    parsed, failures = _parse_fetched(fetched, max_body_bytes, parse_workers)
    indexed = 0
    for row in selected:
        key = (row["warc_filename"], int(row["warc_record_offset"]), int(row["warc_record_length"]))
        response = parsed.get(key)
        if response is None:
            continue
        record_key = fetcher.record_key(*key)
        index.add(record_key, row["host"], row["normalized_path"], response)
        indexed += 1
    index.commit()
    return {"soft404_indexed_count": indexed, "soft404_index_failure_count": failures}


def _parse_fetched(fetched: dict[tuple, bytes | Exception], max_body_bytes: int,
                   parse_workers: int) -> tuple[dict[tuple, ParsedResponse], int]:
    valid = {key: raw for key, raw in fetched.items() if not isinstance(raw, Exception)}
    failures = len(fetched) - len(valid)
    if not valid:
        return {}, failures
    workers = max(1, parse_workers)
    if workers == 1:
        parsed = {}
        for key, raw in valid.items():
            try:
                parsed[key] = parse_warc_record(raw, max_body_bytes=max_body_bytes)
            except Exception:
                failures += 1
        return parsed, failures
    parsed = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(parse_warc_record, raw, max_body_bytes): key for key, raw in valid.items()}
        for future, key in futures.items():
            try:
                parsed[key] = future.result()
            except Exception:
                failures += 1
    return parsed, failures
