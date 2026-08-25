from __future__ import annotations

import re


PROVIDERS = re.compile(r"(?:github\.io|herokuapp\.com|azurewebsites\.net|cloudfront\.net|netlify\.app|vercel\.app|amazonaws\.com)$", re.I)


def assess_takeover(host: str, registered_domain: str, cname_chain: list[str] | None,
                    provider_fingerprint: bool = False, target_exists: bool | None = None) -> dict | None:
    """Assess supplied DNS evidence only; never claims or registers resources."""
    chain = cname_chain or []
    if host == registered_domain or not chain:
        return None
    target = chain[-1].rstrip(".")
    if not PROVIDERS.search(target):
        return None
    # Direct provider hosts are provider assets, not dangling custom domains.
    if PROVIDERS.search(host):
        return None
    confidence = 0.35 + (0.25 if provider_fingerprint else 0) + (0.25 if target_exists is False else 0)
    return {"signal": "TAKEOVER_HINT", "provider_target": target,
            "dns_evidence_present": True, "target_exists": target_exists,
            "confidence": round(min(confidence, 0.85), 2),
            "notes": "Passive hint only; resource claiming is prohibited."}
