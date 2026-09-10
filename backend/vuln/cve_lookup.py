from __future__ import annotations
import os,time
from dataclasses import dataclass,field,asdict
from typing import List
import requests
NVD="https://services.nvd.nist.gov/rest/json/cves/2.0"
@dataclass
class Finding:
    cve_id:str;cvss:float;severity:str;summary:str;product:str;version:str;references:List[str]=field(default_factory=list)
    @property
    def remediation(self):
        b=f"Review {self.cve_id} ({self.severity}, CVSS {self.cvss})."
        return b+(f" Patch/upgrade {self.product} {self.version} or restrict it." if self.severity in ("CRITICAL","HIGH") else f" Assess {self.product} {self.version}.")
def _sev(s): return "CRITICAL" if s>=9 else "HIGH" if s>=7 else "MEDIUM" if s>=4 else "LOW" if s>0 else "NONE"
def _cvss(m):
    for k in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
        a=m.get(k)
        if a:
            try: return float(a[0]["cvssData"]["baseScore"])
            except Exception: continue
    return 0.0
def lookup(product,version="",rpp=5):
    product=(product or "").strip()
    if not product: return []
    h={"apiKey":os.getenv("NVD_API_KEY")} if os.getenv("NVD_API_KEY") else {}
    try:
        pr={"keywordSearch":f"{product} {version}".strip(),"resultsPerPage":rpp}
        r=requests.get(NVD,params=pr,headers=h,timeout=25)
        if r.status_code==429: time.sleep(6); r=requests.get(NVD,params=pr,headers=h,timeout=25)
        r.raise_for_status(); data=r.json()
    except requests.RequestException: return []
    out=[]
    for it in data.get("vulnerabilities",[]):
        cve=it.get("cve",{}); summ=next((d.get("value","") for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
        sc=_cvss(cve.get("metrics",{})); refs=[x.get("url","") for x in cve.get("references",[])][:3]
        out.append(Finding(cve.get("id",""),sc,_sev(sc),summ[:280],product,version,refs))
    return out
def finding_to_dict(f):
    d=asdict(f); d["remediation"]=f.remediation; return d
