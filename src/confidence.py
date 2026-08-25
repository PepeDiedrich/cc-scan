from __future__ import annotations

from datetime import datetime, timezone


def freshness(observed_at, now: datetime | None = None) -> tuple[int | None, float]:
    if not observed_at:
        return None, 0.25
    if isinstance(observed_at, str):
        observed_at = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    days = max(0, (now - observed_at).days)
    if days <= 30:
        return days, 1.0
    if days <= 90:
        return days, round(1.0 - (days - 30) * 0.005, 3)
    return days, round(max(0.1, 0.7 * (0.5 ** ((days - 90) / 365))), 3)


def overall_confidence(*, product: float, version: float | None, endpoint: float | None,
                       configuration: float | None, cve_match: float | None,
                       response: float, freshness_score: float) -> float:
    values = {
        "product": (product, 0.30), "version": (version, 0.20),
        "endpoint": (endpoint, 0.15), "configuration": (configuration, 0.10),
        "cve": (cve_match, 0.15), "response": (response, 0.05),
        "freshness": (freshness_score, 0.05),
    }
    # Missing optional evidence is uncertainty, not zero evidence. It contributes
    # no numerator but its weight remains in the denominator.
    return round(sum(float(value or 0.0) * weight for value, weight in values.values()), 3)


def evidence_state(product_confidence: float, cve: dict | None,
                   explicit_archived_proof: bool = False) -> str:
    if explicit_archived_proof:
        return "CONFIRMED"
    if cve and cve.get("version_range_matches"):
        return "LIKELY_VULNERABLE"
    if cve:
        return "CVE_CANDIDATE"
    return "PRODUCT_DETECTED"
