from __future__ import annotations
import json,shutil,subprocess
from typing import Callable,Dict,List,Optional
def _log(cb,m):
    if cb: cb(m)
def have(b): return shutil.which(b) is not None
def engine_status(): return {"naabu":have("naabu"),"nuclei":have("nuclei"),"nmap":have("nmap")}
def naabu_discover(targets,top_ports="1000",rate=1000,privileged=False,log_cb=None):
    if not have("naabu"):
        _log(log_cb,"[naabu] not installed - using nmap discovery"); return {}
    st="s" if privileged else "c"
    cmd=["naabu","-silent","-json","-no-color","-top-ports",str(top_ports),"-rate",str(rate),"-s",st,"-host",",".join(targets)]
    _log(log_cb,"$ "+" ".join(cmd)); found={}
    try: proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    except OSError as e:
        _log(log_cb,f"[naabu] failed: {e}"); return {}
    for line in proc.stdout:
        line=line.strip()
        if not line: continue
        try: o=json.loads(line)
        except json.JSONDecodeError: continue
        ip=o.get("ip") or o.get("host"); port=o.get("port")
        if ip and isinstance(port,int):
            b=found.setdefault(ip,[])
            if port not in b: b.append(port); _log(log_cb,f"[naabu] {ip}:{port}")
    proc.wait()
    for ip in found: found[ip].sort()
    _log(log_cb,f"[naabu] {sum(len(v) for v in found.values())} port(s)/{len(found)} host(s)")
    return found
def naabu_ports_arg(found): return ",".join(str(p) for p in sorted({p for v in found.values() for p in v}))
_SEV={"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW","info":"INFO","unknown":"NONE"}
def _nt(hosts):
    web={80,8080,8000,8888};tls={443,8443};out=[]
    for h in hosts:
        ip=h.get("ip")
        for s in h.get("services",[]):
            p=s.get("port");n=(s.get("name") or "").lower()
            if p in tls or "https" in n or "ssl" in n: out.append(f"https://{ip}:{p}")
            elif p in web or "http" in n: out.append(f"http://{ip}:{p}")
            else: out.append(f"{ip}:{p}")
    return out
def _ip(m):
    for pfx in ("https://","http://"):
        if m.startswith(pfx): m=m[len(pfx):]
    return m.split("/")[0].split(":")[0]
def nuclei_validate(hosts,severities="critical,high,medium,low",extra_args=None,log_cb=None):
    if not have("nuclei"):
        _log(log_cb,"[nuclei] not installed - skipping"); return {}
    tg=_nt(hosts)
    if not tg:
        _log(log_cb,"[nuclei] no services"); return {}
    cmd=["nuclei","-silent","-jsonl","-no-color","-severity",severities]+(extra_args or [])
    _log(log_cb,"$ "+" ".join(cmd)+f"  (< {len(tg)} targets)"); res={}
    try: proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
    except OSError as e:
        _log(log_cb,f"[nuclei] failed: {e}"); return {}
    proc.stdin.write("\n".join(tg)+"\n"); proc.stdin.close()
    for line in proc.stdout:
        line=line.strip()
        if not line: continue
        try: o=json.loads(line)
        except json.JSONDecodeError: continue
        info=o.get("info",{});sev=_SEV.get((info.get("severity") or "unknown").lower(),"NONE");matched=o.get("matched-at") or o.get("host") or ""
        res.setdefault(_ip(matched),[]).append({"template_id":o.get("template-id",""),"name":info.get("name",""),"severity":sev,"matched_at":matched,"description":(info.get("description") or "")[:240]})
        _log(log_cb,f"[nuclei] {sev}: {o.get('template-id','')} @ {matched}")
    proc.wait(); _log(log_cb,f"[nuclei] {sum(len(v) for v in res.values())} finding(s)")
    return res
