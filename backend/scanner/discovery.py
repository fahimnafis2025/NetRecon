"""NetRecon discovery scanner. nmap + optional Naabu->nmap->Nuclei. Live log, progress, cancel, probe, device intel."""
from __future__ import annotations
import os, re, shutil, subprocess, tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional, Tuple
from .deviceintel import classify, risk_notes
from .portinfo import describe_dict
from .ouilookup import enrich_vendor
from .engines import naabu_discover, naabu_ports_arg, nuclei_validate, engine_status

PROFILES: Dict[str, dict] = {
    "discovery": {"label": "Ping Sweep", "icon": "radar", "stealth": 4,
        "blurb": "Find live hosts only. Seconds.",
        "what_it_does": "Host discovery only (-sn). Fastest way to a device count.",
        "speed": "Very fast", "detection_risk": "Low", "needs_privilege": False,
        "args": ["-sn"], "engine": "nmap"},
    "safe": {"label": "Safe (Default)", "icon": "shield", "stealth": 3,
        "blurb": "Fast, balanced. Top 200 ports + service detection.",
        "what_it_does": "Top-200 ports, -sV --version-light, -T4, bounded retries, 4-min host cap, -Pn.",
        "speed": "Fast", "detection_risk": "Low-Moderate", "needs_privilege": False,
        "args": ["-sV", "--version-light", "-T4", "--top-ports", "200", "--max-retries", "2", "--host-timeout", "4m", "-Pn"], "engine": "nmap"},
    "quick": {"label": "Quick Recon", "icon": "bolt", "stealth": 2,
        "blurb": "Very fast top-100 pass.",
        "what_it_does": "Service detection on the top 100 ports at -T4, -Pn.",
        "speed": "Very fast", "detection_risk": "Moderate", "needs_privilege": False,
        "args": ["-sV", "--version-light", "-T4", "--top-ports", "100", "-Pn"], "engine": "nmap"},
    "turbo": {"label": "Turbo (Naabu + nmap)", "icon": "bolt", "stealth": 1,
        "blurb": "Naabu finds ports fast, nmap fingerprints them.",
        "what_it_does": "Naabu sweeps top 1000 ports at wire speed, then nmap -sV on open ports. Falls back to nmap if Naabu absent.",
        "speed": "Very fast", "detection_risk": "High", "needs_privilege": False,
        "args": ["-sV", "-T4", "-Pn"], "engine": "naabu+nmap"},
    "validate": {"label": "Validate (Naabu+nmap+Nuclei)", "icon": "bug", "stealth": 1,
        "blurb": "Full pipeline: discover -> fingerprint -> vuln-check.",
        "what_it_does": "Naabu -> nmap -sV -> Nuclei detection templates for real, template-based findings. Nuclei skipped if not installed.",
        "speed": "Moderate", "detection_risk": "Very High", "needs_privilege": False,
        "args": ["-sV", "-T4", "-Pn"], "engine": "naabu+nmap+nuclei"},
    "thorough": {"label": "Thorough (+OS, top 1000)", "icon": "layers", "stealth": 2,
        "blurb": "Top 1000 ports + OS detection.",
        "what_it_does": "nmap -sV -O on top 1000 ports, -T4, -Pn. Adds device typing.",
        "speed": "Moderate-Slow", "detection_risk": "High", "needs_privilege": True,
        "args": ["-sV", "-O", "-T4", "--top-ports", "1000", "--max-retries", "2", "-Pn"], "engine": "nmap"},
    "full": {"label": "Full (All Ports)", "icon": "grid", "stealth": 1,
        "blurb": "All 65,535 TCP ports.",
        "what_it_does": "nmap -sV -O -p- -T4 -Pn. Thorough, slow, loud.",
        "speed": "Slow", "detection_risk": "Very High", "needs_privilege": True,
        "args": ["-sV", "-O", "-T4", "-p-", "--max-retries", "2", "-Pn"], "engine": "nmap"},
    "stealth": {"label": "Stealth (Careful)", "icon": "eyeoff", "stealth": 5,
        "blurb": "Quiet half-open SYN scan, slow timing.",
        "what_it_does": "SYN scan (-sS) at -T2 over top 200 ports, -Pn. Lowest footprint. Needs sudo.",
        "speed": "Slow", "detection_risk": "Lower", "needs_privilege": True,
        "args": ["-sS", "-T2", "--top-ports", "200", "-Pn"], "engine": "nmap"},
}
DEFAULT_PROFILE = "safe"
MODIFIERS: Dict[str, dict] = {
    "os_detect": {"label": "OS detection  (-O)", "desc": "Add OS fingerprinting for better device typing. Needs sudo/admin.", "args": ["-O"], "needs_privilege": True},
    "top_1000": {"label": "Scan top 1000 ports", "desc": "Widen the fast default from top-200 to top-1000. Slower, more thorough.", "args": ["--top-ports", "1000"], "needs_privilege": False},
    "default_scripts": {"label": "Default scripts  (-sC)", "desc": "Run nmap's safe default NSE scripts for extra service detail.", "args": ["-sC"], "needs_privilege": False},
    "udp_add": {"label": "Also scan UDP  (-sU top 100)", "desc": "Add a UDP sweep of the top 100 ports (DNS/SNMP/TFTP). Needs privilege.", "args": ["-sU", "--top-ports", "100"], "needs_privilege": True},
}
def profile_catalog():
    out = []
    for key, meta in PROFILES.items():
        item = {"key": key, "command_preview": "nmap " + " ".join(meta["args"]) + " <target>"}
        item.update({k: v for k, v in meta.items() if k != "args"}); item["args"] = list(meta["args"]); out.append(item)
    return out
def modifier_catalog(): return [{"key": k, **v} for k, v in MODIFIERS.items()]
@dataclass
class Service:
    port: int; protocol: str; state: str; name: str = ""; product: str = ""; version: str = ""; extrainfo: str = ""
    @property
    def banner(self): return " ".join(p for p in (self.product, self.version, self.extrainfo) if p).strip()
@dataclass
class Host:
    ip: str; hostname: str = ""; status: str = "up"; mac: str = ""; vendor: str = ""; os_guess: str = ""; os_accuracy: int = 0
    device_type: str = "unknown"; friendly_vendor: str = ""; identity_note: str = ""; confidence: str = "low"
    risks: List[dict] = field(default_factory=list); nuclei: List[dict] = field(default_factory=list); services: List[Service] = field(default_factory=list)
def _require_nmap():
    p = shutil.which("nmap")
    if not p: raise RuntimeError("nmap not found on PATH. Install: 'sudo apt install nmap'.")
    return p
def _is_privileged():
    if os.name == "nt": return True
    try: return os.geteuid() == 0
    except AttributeError: return False
_RAW = {"-O", "--osscan-guess", "-sS", "-sN", "-sF", "-sX", "-sU", "-A"}
def _sanitize(args, priv): return list(args) if (priv or os.name == "nt") else [a for a in args if a not in _RAW]
_PCT = re.compile(r"About ([\d.]+)% done"); _REMAIN = re.compile(r"\(([^)]*remaining)\)")
_GENUINE_HOST_REASONS = {
    "arp-response", "conn-refused", "echo-reply", "netmask-reply", "port-unreach",
    "reset", "syn-ack", "tcp-response", "timestamp-reply", "udp-response",
}
def _execute(cmd, progress_cb, log_cb, register_proc):
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
    if register_proc: register_proc(proc)
    for line in proc.stderr:
        line = line.rstrip()
        if not line: continue
        if log_cb: log_cb(line)
        m = _PCT.search(line)
        if m and progress_cb:
            r = _REMAIN.search(line); progress_cb(float(m.group(1)), "Scanning", r.group(1) if r else "")
    return proc.wait()
def run_scan(targets, profile=DEFAULT_PROFILE, modifiers=None, extra_args=None, progress_cb=None, log_cb=None, register_proc=None):
    nmap = _require_nmap(); meta = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE]); engine = meta.get("engine", "nmap"); priv = _is_privileged()
    if log_cb:
        st = engine_status(); log_cb(f"engines: nmap={st['nmap']} naabu={st['naabu']} nuclei={st['nuclei']}")
    found = {}
    naabu_ports = ""
    if "naabu" in engine:
        found = naabu_discover(targets, top_ports="1000", privileged=priv, log_cb=log_cb)
        if found: naabu_ports = naabu_ports_arg(found)
    args = list(meta["args"])
    for mkey in (modifiers or []):
        m = MODIFIERS.get(mkey)
        if m: args += list(m["args"])
    if naabu_ports:
        args += ["-p", naabu_ports]
        if log_cb: log_cb(f"[pipeline] handing {len(naabu_ports.split(','))} naabu port(s) to nmap")
    if extra_args: args += list(extra_args)
    seen, dedup = set(), []
    for a in args:
        if a in ("-Pn", "-sC", "-O") and a in seen: continue
        seen.add(a); dedup.append(a)
    args = _sanitize(dedup, priv)
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf: xml_path = tf.name
    try:
        cmd = [nmap, "-v", "--stats-every", "1s"] + args + ["-oX", xml_path] + list(targets)
        if log_cb: log_cb("$ " + " ".join(cmd))
        if progress_cb: progress_cb(1.0, "Starting nmap", "")
        _execute(cmd, progress_cb, log_cb, register_proc)
        if progress_cb: progress_cb(100.0, "Parsing results", "")
        hosts = _parse_xml(xml_path, confirmed_ips=set(found))
        if log_cb: log_cb(f"parsed {len(hosts)} live host(s).")
    finally:
        try: os.unlink(xml_path)
        except OSError: pass
    for h in hosts: _apply_intel(h)
    if "nuclei" in engine and hosts:
        hd = [host_to_dict(h) for h in hosts]; nres = nuclei_validate(hd, log_cb=log_cb); by_ip = {h.ip: h for h in hosts}
        for ip, findings in nres.items():
            if ip in by_ip: by_ip[ip].nuclei = findings
    return hosts, priv
def _apply_intel(host):
    ports = [s.port for s in host.services]
    if host.mac: host.vendor = enrich_vendor(host.mac, host.vendor)
    info = classify(host.os_guess, host.os_accuracy, host.vendor, host.hostname, ports)
    host.device_type = info["device_type"]; host.friendly_vendor = info["friendly_vendor"]
    host.identity_note = info["identity_note"]; host.confidence = info["confidence"]; host.risks = risk_notes(ports)
def _parse_xml(xml_path, confirmed_ips=None, allow_synthetic=False):
    confirmed_ips = confirmed_ips or set()
    hosts = []
    try: tree = ET.parse(xml_path)
    except (ET.ParseError, FileNotFoundError): return hosts
    for hnode in tree.getroot().findall("host"):
        status = hnode.find("status")
        if status is not None and status.get("state") == "down": continue
        reason = status.get("reason", "") if status is not None else ""
        ip = mac = vendor = ""
        for addr in hnode.findall("address"):
            t = addr.get("addrtype")
            if t == "ipv4": ip = addr.get("addr", "")
            elif t == "mac": mac = addr.get("addr", ""); vendor = addr.get("vendor", "")
        if not ip: continue
        hn = hnode.find("hostnames/hostname"); hostname = hn.get("name", "") if hn is not None else ""
        os_guess, os_acc = "", 0; osm = hnode.find("os/osmatch")
        if osm is not None:
            os_guess = osm.get("name", "")
            try: os_acc = int(osm.get("accuracy", "0"))
            except ValueError: os_acc = 0
        services = []
        for port in hnode.findall("ports/port"):
            ps = port.find("state")
            if ps is None or ps.get("state") != "open": continue
            svc = port.find("service")
            services.append(Service(port=int(port.get("portid", "0")), protocol=port.get("protocol", "tcp"), state="open",
                name=svc.get("name", "") if svc is not None else "", product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "", extrainfo=svc.get("extrainfo", "") if svc is not None else ""))
        active = allow_synthetic or reason in _GENUINE_HOST_REASONS or ip in confirmed_ips or bool(services)
        if not active: continue
        hosts.append(Host(ip=ip, hostname=hostname, mac=mac, vendor=vendor, os_guess=os_guess, os_accuracy=os_acc, services=services))
    return hosts
def host_to_dict(h):
    d = asdict(h); d["services"] = [{**asdict(s), "banner": s.banner, "info": describe_dict(s.port, s.name)} for s in h.services]; return d
_PROBE = {"quick": ["-sV", "-T4", "--top-ports", "100"], "standard": ["-sV", "-O", "-T3", "--top-ports", "1000"], "thorough": ["-sV", "-O", "-T3", "-p-", "-sC"]}
def probe_host(ip, depth="standard", skip_ping=True, progress_cb=None, log_cb=None, register_proc=None):
    args = list(_PROBE.get(depth, _PROBE["standard"]))
    if skip_ping: args = ["-Pn"] + args
    nmap = _require_nmap(); priv = _is_privileged(); args = _sanitize(args, priv)
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf: xml_path = tf.name
    try:
        cmd = [nmap, "-v", "--stats-every", "1s"] + args + ["-oX", xml_path, ip]
        if log_cb: log_cb("$ " + " ".join(cmd))
        _execute(cmd, progress_cb, log_cb, register_proc); hosts = _parse_xml(xml_path, allow_synthetic=skip_ping)
    finally:
        try: os.unlink(xml_path)
        except OSError: pass
    if not hosts: return None
    h = hosts[0]; _apply_intel(h); return host_to_dict(h)
