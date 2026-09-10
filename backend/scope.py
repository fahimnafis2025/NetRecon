from __future__ import annotations
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import List
class OutOfScopeError(Exception): pass
def _now(): return datetime.now(timezone.utc).isoformat()
@dataclass
class Authorization:
    authorized_by: str; engagement_id: str
    allowed_cidrs: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now); note: str = ""
    def networks(self): return [ip_network(c.strip(),strict=False) for c in self.allowed_cidrs if c.strip()]
def _resolve(h):
    h=(h or "").strip()
    if not h: return []
    try: return [str(ip_address(h))]
    except ValueError: pass
    try:
        n=ip_network(h,strict=False); return [str(n.network_address),str(n.broadcast_address)]
    except ValueError: pass
    try: return sorted({i[4][0] for i in socket.getaddrinfo(h,None)})
    except socket.gaierror: return []
def is_in_scope(t,a):
    nets=a.networks()
    if not nets: return False
    ips=_resolve(t)
    if not ips: return False
    return all(any(ip_address(ip) in n for n in nets) for ip in ips)
def enforce(targets,a):
    if not a.networks(): raise OutOfScopeError(f"Refused: empty allowlist for '{a.engagement_id}'.")
    out=[]
    for t in targets:
        t=(t or "").strip()
        if not t: continue
        if not is_in_scope(t,a): raise OutOfScopeError(f"Refused: '{t}' OUTSIDE scope for '{a.engagement_id}' (allowed: {', '.join(a.allowed_cidrs) or 'none'}).")
        out.append(t)
    if not out: raise OutOfScopeError(f"Refused: no valid targets for '{a.engagement_id}'.")
    return out
