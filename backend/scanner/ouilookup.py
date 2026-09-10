from __future__ import annotations
import os,re
from typing import Dict
_B={"FCFC48":"Apple","F0D1A9":"Apple","A4C361":"Apple","3C0754":"Apple","D0817A":"Apple","8866A5":"Apple",
 "94E5B5":"Ubee Interactive","0AF329":"Ubee Interactive","B49DFD":"Shenzhen SDMC Technology","68C901":"Zhuolian Communication",
 "D65F96":"Samsung","5CE5B8":"Samsung","F62BC7":"Samsung","E4E749":"Roku","B0A737":"Roku","D0D2B0":"Amazon Technologies",
 "1C129D":"Google","3C5AB4":"Google","54D0B4":"Sonos","2405F5":"Hikvision","3CEF8C":"Dahua","2C55D3":"Wyze",
 "50EC50":"Espressif (ESP)","240AC4":"Espressif (ESP)","ACF878":"Tuya Smart","001788":"Philips Hue","50C7BF":"TP-Link/Kasa",
 "B0BE76":"TP-Link","00248C":"ASUSTek","44D9E7":"Ubiquiti","6C2779":"Nintendo","F8461C":"Sony PlayStation","0017FA":"Microsoft Xbox",
 "001132":"Synology","0011D8":"QNAP","B827EB":"Raspberry Pi","DCA632":"Raspberry Pi","080027":"Oracle VirtualBox",
 "005056":"VMware","000C29":"VMware","1C1B0D":"MikroTik","001E58":"D-Link","3C8CF8":"Midea","44D8B5":"ecobee","18B430":"Nest Labs"}
_F=os.path.join(os.path.dirname(__file__),"oui.txt"); _L=None
def _norm(m): return re.sub(r"[^0-9A-Fa-f]","",m or "").upper()
def _load():
    t={}
    if not os.path.exists(_F): return t
    try:
        for line in open(_F,encoding="utf-8",errors="ignore"):
            if "(base 16)" in line:
                p=line.split("(base 16)"); pre=_norm(p[0])[:6]; v=p[1].strip()
                if pre and v: t[pre]=v
    except OSError: pass
    return t
def _tab():
    global _L
    if _L is None: _L=dict(_B); _L.update(_load())
    return _L
def lookup_vendor(mac):
    n=_norm(mac); return _tab().get(n[:6],"") if len(n)>=6 else ""
def enrich_vendor(mac,existing=""): return existing.strip() if (existing and existing.strip()) else lookup_vendor(mac)
