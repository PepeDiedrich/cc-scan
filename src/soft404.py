from __future__ import annotations

import re

from .response_parser import ParsedResponse


NOT_FOUND = re.compile(r"\b(?:not found|page does not exist|404 error|no such (?:page|file))\b", re.I)
WAF = re.compile(r"(?:access denied|request blocked|web application firewall|cloudflare ray id)", re.I)
CDN_ERROR = re.compile(r"(?:error from cloudfront|varnish cache server|cdn error|upstream connect error)", re.I)


def probabilities(response: ParsedResponse, path: str,
                  host_responses: list[tuple[str, ParsedResponse]] | None = None,
                  global_context: dict[str, int | bool] | None = None) -> dict[str, float]:
    soft, spa = 0.0, 0.0
    if response.status == 200 and NOT_FOUND.search(response.text):
        soft += 0.70
    title = (response.title or "").lower()
    if response.status == 200 and "404" in title:
        soft += 0.25
    peers = host_responses or []
    same_hash_paths = [p for p, r in peers if r.normalized_body_hash == response.normalized_body_hash and p != path]
    global_count = int((global_context or {}).get("same_hash_path_count", 0))
    same_hash_count = max(len(same_hash_paths), global_count)
    if same_hash_count:
        soft += min(0.65, 0.20 + same_hash_count * 0.15)
        if (global_context or {}).get("same_hash_has_root") or any(p in ("/", "/index.html") for p in same_hash_paths):
            spa += 0.70
    if re.search(r"<div[^>]+id=[\"'](?:root|app)[\"']", response.text, re.I) and response.artifacts.get("script_src"):
        spa += 0.25
    generic = 0.85 if WAF.search(response.text) else 0.0
    cdn = 0.85 if CDN_ERROR.search(response.text) else 0.0
    login = 0.6 if re.search(r'(?is)<input[^>]+type=[\"\']password[\"\']', response.text) else 0.0
    return {"soft_404_probability": round(min(soft, 1.0), 3),
            "spa_fallback_probability": round(min(spa, 1.0), 3),
            "generic_waf_probability": generic, "cdn_error_probability": cdn,
            "generic_login_probability": login}
