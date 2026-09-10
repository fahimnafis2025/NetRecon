from __future__ import annotations
from typing import Dict,List,Tuple
VENDOR=[("ubee","Ubee (ISP gateway)","router / gateway"),("sdmc","SDMC (Wi-Fi mesh / STB)","Wi-Fi mesh / set-top box"),
 ("arris","ARRIS","router / gateway"),("zhuolian","Zhuolian","IoT / smart device"),("cisco","Cisco","router / switch"),
 ("ubiquiti","Ubiquiti","router / AP"),("tp-link","TP-Link","router / AP"),("netgear","NETGEAR","router / AP"),
 ("d-link","D-Link","router / AP"),("asustek","ASUS","router / AP"),("mikrotik","MikroTik","router / AP"),
 ("synology","Synology","NAS / storage"),("qnap","QNAP","NAS / storage"),("hewlett","HP","printer / PC"),("brother","Brother","printer"),
 ("canon","Canon","printer"),("epson","Epson","printer"),("hikvision","Hikvision","IP camera"),("dahua","Dahua","IP camera"),
 ("wyze","Wyze","IP camera"),("apple","Apple","Apple device"),("samsung","Samsung","phone / TV"),("xiaomi","Xiaomi","phone / IoT"),
 ("huawei","Huawei","phone / network"),("google","Google","IoT / media"),("amazon","Amazon","IoT / media"),("roku","Roku","media streamer"),
 ("sonos","Sonos","voice / speaker"),("espressif","Espressif (ESP)","IoT / embedded"),("tuya","Tuya","IoT / smart home"),
 ("philips","Philips Hue","smart bulb"),("nintendo","Nintendo","game console"),("sony playstation","Sony PlayStation","game console"),
 ("xbox","Microsoft Xbox","game console"),("nest","Nest","IoT / smart home"),("ecobee","ecobee","thermostat"),("midea","Midea","smart appliance"),
 ("raspberry","Raspberry Pi","single-board computer"),("intel","Intel","PC / laptop"),("dell","Dell","PC / laptop"),
 ("lenovo","Lenovo","PC / laptop"),("liteon","Liteon","PC / laptop"),("vmware","VMware","virtual machine"),
 ("virtualbox","VirtualBox","virtual machine"),("microsoft","Microsoft","PC / VM")]
HOST=[("d222ah","SDMC D222AH Wi-Fi 6E mesh extender"),("gen9","Gateway (ISP router)"),("iphone","Apple iPhone"),("ipad","Apple iPad"),
 ("macbook","Apple MacBook"),("android","Android device"),("galaxy","Samsung Galaxy"),("-s20","Samsung Galaxy S20"),("-s22","Samsung Galaxy S22"),
 ("pixel","Google Pixel"),("desktop-","Windows PC"),("laptop","Laptop"),("kali","Kali Linux (scanner box)"),("raspberry","Raspberry Pi"),
 ("pi-hole","Pi-hole (Raspberry Pi)"),("printer","Printer"),("nas","NAS / storage"),("roku","Roku"),("firetv","Amazon Fire TV"),
 ("chromecast","Google Chromecast"),("echo","Amazon Echo"),("nintendo","Nintendo"),("playstation","PlayStation"),("xbox","Xbox"),
 ("-tv","Smart TV"),("bravia","Sony Bravia TV"),("wyze","Wyze camera"),("ring","Ring doorbell")]
RISK={23:("Telnet - unencrypted remote admin","high"),21:("FTP - cleartext file transfer","high"),2323:("Telnet (alt)","high"),
 513:("rlogin - legacy","high"),514:("rsh - legacy","high"),69:("TFTP - unauthenticated","high"),80:("HTTP - unencrypted admin UI","medium"),
 8080:("HTTP-alt admin UI","medium"),161:("SNMP - default 'public'?","medium"),445:("SMB - file sharing","medium"),3389:("RDP","medium"),
 5900:("VNC - weak auth?","medium"),1900:("UPnP/SSDP exposure","info"),7547:("TR-069 ISP mgmt","info"),5555:("ADB over TCP","high")}
_PR={515,631,9100};_NA={139,445,111,2049,548,5000};_RO={53,67,68,1900,7547,8291};_WE={80,443,8080,8443};_CAM={554,8554};_ST={8008,8009,8060}
def _mv(v):
    v=(v or "").lower()
    for n,f,k in VENDOR:
        if n in v: return f,k
    return (v or ""),""
def _mh(h):
    h=(h or "").lower()
    for n,note in HOST:
        if n in h: return note
    return ""
def classify(os_guess,acc,vendor,hostname,ports):
    ports=set(ports);os_l=(os_guess or "").lower();fv,vc=_mv(vendor);hn=_mh(hostname);dt,conf,bits="unknown","low",[]
    if hn:
        bits.append(hn);hl=hn.lower()
        if any(k in hl for k in ("mesh","router","gateway")): dt="router / AP"
        elif any(k in hl for k in ("iphone","ipad","android","galaxy","pixel")): dt="phone / mobile"
        elif "tv" in hl or "bravia" in hl: dt="smart TV"
        elif any(k in hl for k in ("roku","firetv","chromecast")): dt="media streamer"
        elif "echo" in hl: dt="voice assistant"
        elif any(k in hl for k in ("wyze","ring","cam")): dt="IP camera"
        elif any(k in hl for k in ("playstation","xbox","nintendo")): dt="game console"
        elif "printer" in hl: dt="printer"
        elif "nas" in hl: dt="NAS / storage"
        elif any(k in hl for k in ("pc","laptop","macbook","windows")): dt="workstation / PC"
        elif "kali" in hl or "raspberry" in hl or "pi-hole" in hl: dt="Linux host"
        else: dt="IoT / appliance"
        conf="medium"
    if acc and acc>=90 and os_l:
        if "windows server" in os_l: dt,conf="server","high"
        elif "windows" in os_l: dt,conf="workstation / PC","high"
        elif any(k in os_l for k in ("routeros","junos","openwrt","router")): dt,conf="router / switch","high"
        elif "printer" in os_l: dt,conf="printer","high"
        elif any(k in os_l for k in ("android","iphone")): dt,conf="phone / mobile","high"
        elif any(k in os_l for k in ("mac os","macos","darwin")): dt,conf="Apple computer","high"
        elif "linux" in os_l: dt,conf="Linux host","high"
    if vc:
        bits.append(f"MAC vendor: {fv}")
        if dt=="unknown": dt,conf=vc,"medium"
    if dt=="unknown":
        if len(ports&_ST)>=2 or 8060 in ports: dt,conf="media streamer","medium"
        elif (ports&_CAM) and (ports&{80,443}): dt,conf="IP camera","medium"
        elif len(ports&_PR)>=2 or 9100 in ports: dt,conf="printer","medium"
        elif len(ports&_NA)>=2: dt,conf="NAS / storage","medium"
        elif len(ports&_RO)>=2: dt,conf="router / AP","medium"
        elif len(ports&_WE)>=2: dt,conf="web server / appliance","low"
        elif 3389 in ports: dt,conf="workstation / PC","low"
    return {"device_type":dt,"friendly_vendor":fv,"identity_note":" · ".join(bits),"confidence":conf}
def risk_notes(ports): return [{"port":p,"note":RISK[p][0],"level":RISK[p][1]} for p in sorted(set(ports)) if p in RISK]
