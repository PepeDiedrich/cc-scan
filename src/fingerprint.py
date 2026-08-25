from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .response_parser import ParsedResponse


def load_fingerprints(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _source_text(source: str, response: ParsedResponse) -> str:
    if source == "body":
        return response.text
    if source == "title":
        return response.title or ""
    if source == "header":
        selected = ("server", "x-powered-by", "via", "location", "www-authenticate",
                    "x-generator", "x-grafana-version", "x-jenkins", "x-teamcity-node-id",
                    "x-gitlab-meta", "x-elastic-product", "x-owa-version", "x-feserver",
                    "x-calculatedbetarget", "microsoftsharepointteamservices")
        return "\n".join(f"{k}: {response.headers[k]}" for k in selected if k in response.headers)
    return ""


def detect_product(row: dict[str, Any], response: ParsedResponse,
                   definitions: dict[str, Any]) -> tuple[str, float, list[dict[str, Any]]]:
    hint = row.get("product_hint") or "Unknown"
    evidence: list[dict[str, Any]] = []
    scores: dict[str, list[float]] = {}
    if hint not in ("Unknown", "Generic security endpoint", "Sensitive file", "Git metadata"):
        evidence.append({"type": "url_path", "value": row.get("normalized_path"), "weight": 0.30})
        scores.setdefault(hint, []).append(0.30)
    for product, definition in definitions.items():
        for marker in definition.get("markers", []):
            value = _source_text(marker["source"], response)
            match = re.search(marker["pattern"], value, re.I)
            if match:
                weight = float(marker["weight"])
                evidence.append({"type": marker["source"], "value": match.group(0)[:200], "weight": weight})
                scores.setdefault(product, []).append(weight)
    if not scores:
        return hint, 0.20 if hint not in (None, "Unknown") else 0.0, evidence
    product, weights = max(scores.items(), key=lambda item: 1 - _product(1 - w for w in item[1]))
    confidence = 1 - _product(1 - w for w in weights)
    return product, round(min(confidence, 0.99), 3), evidence


def _product(values):
    result = 1.0
    for value in values:
        result *= value
    return result


SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "DATABASE_URL": re.compile(r"(?im)^\s*DATABASE_URL\s*=\s*\S+"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "ENV_CREDENTIAL": re.compile(r"(?im)^\s*(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY)\s*=\s*\S+"),
}


def detect_secrets(text: str) -> list[dict[str, Any]]:
    """Return only secret types/counts. Never return credential material."""
    findings = []
    for kind, pattern in SECRET_PATTERNS.items():
        count = len(pattern.findall(text))
        if count:
            findings.append({"secret_type": kind, "secret_present": True, "count": count})
    return findings
