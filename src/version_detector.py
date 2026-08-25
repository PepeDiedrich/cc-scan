from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs

from .response_parser import ParsedResponse


@dataclass(frozen=True)
class DetectedVersion:
    product: str
    raw_version: str
    normalized_version: str
    version_source: str
    version_confidence: float


BODY_PATTERNS = {
    "GeoServer": [r"GeoServer(?: version)?[ /:v-]*(\d+(?:\.\d+){1,3}(?:[-._][0-9A-Za-z]+)?)"],
    "Apache Tomcat": [r"Apache Tomcat[/ ](\d+(?:\.\d+){1,3})", r"Apache-Coyote/(\d+(?:\.\d+){1,3})"],
    "Grafana": [r"Grafana(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)"],
    "jQuery": [r"jQuery(?: JavaScript Library)? v?(\d+(?:\.\d+){1,3})"],
    "PDF.js": [r"(?:pdfjsVersion|PDF\.js)[\s=:v'\"]+(\d+(?:\.\d+){1,3})"],
    "Langflow": [r"Langflow(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
}


PATH_PATTERNS = {
    "jQuery": [r"jquery(?:@|[-_/])v?(\d+(?:\.\d+){1,3})"],
    "PDF.js": [r"pdf(?:\.min)?(?:@|[-_/])v?(\d+(?:\.\d+){1,3})"],
}


def normalize_version(raw: str) -> str:
    value = raw.strip().lstrip("vV").replace("_", ".")
    return re.sub(r"[^0-9A-Za-z.+-].*$", "", value)


def detect_version(product: str, path: str, query: str, response: ParsedResponse) -> DetectedVersion | None:
    for pattern in BODY_PATTERNS.get(product, []):
        match = re.search(pattern, response.text, re.I)
        if match:
            raw = match.group(1)
            return DetectedVersion(product, raw, normalize_version(raw), "response_body", 0.95)
    header_text = " ".join(response.headers.get(k, "") for k in ("server", "x-powered-by", "x-grafana-version"))
    for pattern in BODY_PATTERNS.get(product, []):
        match = re.search(pattern, header_text, re.I)
        if match:
            raw = match.group(1)
            return DetectedVersion(product, raw, normalize_version(raw), "response_header", 0.90)
    for key in ("ver", "version", "v"):
        for raw in parse_qs(query, keep_blank_values=True).get(key, []):
            if re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?", raw, re.I):
                return DetectedVersion(product, raw, normalize_version(raw), "url_query", 0.72)
    for pattern in PATH_PATTERNS.get(product, []):
        match = re.search(pattern, path, re.I)
        if match:
            raw = match.group(1)
            return DetectedVersion(product, raw, normalize_version(raw), "url_path", 0.75)
    return None


def version_key(version: str) -> tuple:
    """Natural product-version ordering; handles suffixes without string sorting."""
    parts = re.findall(r"\d+|[A-Za-z]+", version.replace("~", "-"))
    return tuple((0, int(p)) if p.isdigit() else (1, p.lower()) for p in parts)


def compare_versions(left: str, right: str) -> int:
    a, b = version_key(left), version_key(right)
    width = max(len(a), len(b))
    pad = (0, 0)
    a, b = a + (pad,) * (width - len(a)), b + (pad,) * (width - len(b))
    return (a > b) - (a < b)
