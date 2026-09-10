from __future__ import annotations
from typing import Tuple
PORTS={20:("FTP-data","FTP data channel.","Cleartext; prefer SFTP."),21:("FTP","File Transfer Protocol.","Cleartext creds."),
 22:("SSH","Encrypted remote admin.","Restrict; use keys."),23:("Telnet","Legacy remote login.","Cleartext - disable."),
 25:("SMTP","Mail transfer.","Check open relay."),53:("DNS","Name resolution.","Open resolver = amplification."),
 67:("DHCP","IP assignment.","Rogue DHCP = MITM."),69:("TFTP","No-auth file transfer.","Leaks configs."),
 80:("HTTP","Unencrypted web/admin.","No TLS; sniffable."),110:("POP3","Mailbox.","Cleartext unless POP3S."),
 111:("RPCbind","ONC RPC mapper.","Enumerable."),123:("NTP","Time sync.","Amplification risk."),
 135:("MSRPC","Windows RPC mapper.","Lateral-movement surface."),137:("NetBIOS-NS","Legacy name svc.","Leaks host/user."),
 139:("NetBIOS-SSN","Legacy SMB.","Disable NetBIOS."),143:("IMAP","Mailbox.","Cleartext unless IMAPS."),
 161:("SNMP","Device mgmt.","Default 'public' leaks lots."),389:("LDAP","Directory (AD).","Cleartext; enumerable."),
 443:("HTTPS","Encrypted web (TLS).","Check cert/cipher."),445:("SMB","Windows file share/AD.","EternalBlue-class; patch."),
 465:("SMTPS","Encrypted mail.",""),514:("Syslog","Remote logging.","Often UDP/cleartext."),515:("LPD","Printer daemon.","Printer."),
 587:("SMTP-sub","Mail submission.",""),631:("IPP","Internet Printing.","Printer/CUPS."),993:("IMAPS","Encrypted IMAP.",""),
 995:("POP3S","Encrypted POP3.",""),1080:("SOCKS","SOCKS proxy.","Open proxy=pivot."),1400:("Sonos","Sonos control.","Speaker."),
 1433:("MSSQL","MS SQL.","Restrict."),1521:("Oracle","Oracle DB.","Restrict."),1723:("PPTP","Legacy VPN.","Weak crypto."),
 1883:("MQTT","IoT broker.","Often unauth."),1900:("SSDP/UPnP","UPnP discovery.","Auto-opens firewall holes."),
 2049:("NFS","Unix file share.","Check exports."),2323:("Telnet-alt","Legacy login.","Cleartext-disable."),
 3306:("MySQL","MySQL/MariaDB.","Restrict."),3389:("RDP","Remote Desktop.","Ransomware target; MFA."),
 5000:("UPnP/App","Web app/DSM.",""),5001:("App/DSM","Synology DSM.",""),5060:("SIP","VoIP signaling.","Toll-fraud."),
 5353:("mDNS","Bonjour discovery.","Devices announce."),5432:("PostgreSQL","PostgreSQL.","Restrict."),
 5555:("ADB/App","Android Debug Bridge.","ADB/TCP=full control."),5900:("VNC","Remote desktop.","Weak auth?"),
 5985:("WinRM","Win Remote Mgmt.","Lateral-movement."),6379:("Redis","In-memory store.","Unauth=RCE."),
 7547:("TR-069","ISP CWMP.","ISP remote mgmt."),8008:("Chromecast","Cast HTTP.","Streamer."),8009:("Cast","Google Cast.","Streamer."),
 8060:("Roku ECP","Roku control.","Streamer."),8080:("HTTP-alt","Alt/proxy web.","Admin panels."),8291:("Winbox","MikroTik mgmt.","Router admin."),
 8443:("HTTPS-alt","Alt secure web.",""),9100:("JetDirect","Raw printing.","Printer."),9200:("Elasticsearch","Search DB.","Unauth=exposure."),
 27017:("MongoDB","NoSQL DB.","Unauth=exposure."),32400:("Plex","Plex media.","Media server."),62078:("iOS-sync","Apple lockdownd.","iPhone/iPad.")}
def describe(port,name=""):
    if port in PORTS: return PORTS[port]
    if name: return (name,f"nmap service '{name}'.","")
    return (f"port {port}","Unrecognized - inspect banner.","")
def describe_dict(port,name=""):
    n,d,r=describe(port,name); return {"short_name":n,"description":d,"risk_note":r}
