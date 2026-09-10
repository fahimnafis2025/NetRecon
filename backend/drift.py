"""Phase 3 snapshot comparison and asset-state transitions."""
from __future__ import annotations

from backend.risk import port_risk


def _ports(host: dict) -> set[tuple[int, str]]:
    return {(int(service.get("port", 0)), service.get("protocol", "tcp"))
            for service in host.get("services", []) if service.get("state", "open") == "open"}


def _host_map(scan: dict) -> dict[str, dict]:
    return {_stable_asset_key(host): host for host in scan.get("hosts", []) if host.get("active", True)}


def _stable_asset_key(host: dict) -> str:
    mac = "".join(character for character in str(host.get("mac", "")).lower() if character in "0123456789abcdef")
    if mac:
        return f"mac:{mac}"
    identity = "|".join(str(host.get(name, "")).strip().lower() for name in ("hostname", "vendor", "device_type")).strip("|")
    if identity and identity.replace("|", "") not in ("unknown", "unknownunknown"):
        return f"identity:{identity}"
    return f"ip:{str(host.get('ip', '')).strip().lower()}"


def _coverage_allows_closed(scan: dict, port: int) -> bool:
    coverage = scan.get("coverage_signature", {}).get("ports", "")
    if coverage in ("all", "all-ports", "top-1000"):
        return True
    if coverage == "top-100" and port <= 100:
        return True
    if coverage == "top-200" and port <= 200:
        return True
    return False


def detect_changes(baseline: dict | None, current: dict, statuses: dict[str, int], known_hosts=None) -> list[dict]:
    if not baseline:
        return []
    previous = _host_map(baseline)
    if known_hosts:
        previous.update(_host_map({"hosts": known_hosts}))
    latest = _host_map(current)
    events = []

    for key, host in latest.items():
        if key not in previous:
            events.append(_event("new_device", key, host, current, baseline.get("scan_id"), "MEDIUM", 35))
            continue
        previous_ports = _ports(previous[key])
        current_ports = _ports(host)
        for port, protocol in sorted(current_ports - previous_ports):
            severity, score = port_risk(port)
            events.append(_event("new_port", key, host, current, baseline.get("scan_id"), severity, score,
                                 port=port, protocol=protocol))
        for port, protocol in sorted(previous_ports - current_ports):
            if _coverage_allows_closed(current, port):
                events.append(_event("closed_port", key, host, current, baseline.get("scan_id"), "INFO", 0,
                                     port=port, protocol=protocol))

        missed = statuses.get(key, 0)
        if missed:
            events.append(_event("reappeared_device", key, host, current, baseline.get("scan_id"), "LOW", 15))

    for key, host in previous.items():
        if key in latest:
            continue
        missed = statuses.get(key, 0) + 1
        event_type = "device_disappeared" if missed >= 2 else "possible_disappeared"
        score = 25 if missed >= 2 else 15
        severity = "MEDIUM" if missed >= 2 else "LOW"
        events.append(_event(event_type, key, host, current, baseline.get("scan_id"), severity, score,
                             missed_compatible_scans=missed))
    return events


def _event(event_type, stable_key, host, scan, baseline_scan_id, severity, risk_score, **extra):
    return {
        "event_type": event_type,
        "stable_key": stable_key,
        "ip": host.get("ip"),
        "asset_id": host.get("asset_id"),
        "scan_id": scan.get("scan_id"),
        "baseline_scan_id": baseline_scan_id,
        "severity": severity,
        "risk_score": risk_score,
        **extra,
    }
