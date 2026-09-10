"""Deterministic Phase 3 risk scoring."""
from __future__ import annotations

PORT_SEVERITY_OVERRIDES = {
    445: "HIGH",
    3389: "HIGH",
    23: "HIGH",
    5900: "HIGH",
    21: "MEDIUM",
    22: "LOW",
}
PORT_SCORES = {"HIGH": 70, "MEDIUM": 50, "LOW": 25}


def severity_for_score(score: float) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def score_port(port: int) -> int:
    return PORT_SCORES.get(PORT_SEVERITY_OVERRIDES.get(port, ""), 20)


def port_risk(port: int) -> tuple[str, int]:
    score = score_port(port)
    return PORT_SEVERITY_OVERRIDES.get(port, severity_for_score(score)), score


def asset_risk(host: dict, changes: list[dict] | None = None) -> tuple[float, str]:
    scores = [score_port(int(service.get("port", 0))) for service in host.get("services", [])]
    scores.extend(float(event.get("risk_score", 0)) for event in (changes or []))
    scores.extend(float(finding.get("cvss", 0)) * 10 for finding in host.get("findings", []))
    score = min(100.0, max(scores, default=0.0))
    return score, severity_for_score(score)
