# 🔍 CTF Writeups — TraceRouteGone

> Cybersecurity professional transitioning into **SOC / DFIR** roles.  
> CompTIA Security+ | SC-900 | CyberOps Associate | LetsDefend SOC Analyst  

---

## About

I document my investigations from Blue Team CTF competitions here.  
Each writeup covers the full incident response process — from initial triage through to attacker timeline reconstruction, IOC extraction, and reporting.

**Focus areas:** Threat hunting · Incident response · Log analysis · Malware behaviour

---

## Skills Demonstrated

| Tool / Skill | Used In |
|---|---|
| Splunk SPL | CTF5, CTF6 |
| Windows Event Log Analysis (Sysmon) | CTF5, CTF6 |
| PCAP / Wireshark / Zeek | CTF6 |
| Active Directory Attack Techniques | CTF6 |
| DFIR Methodology | CTF5, CTF6 |
| MITRE ATT&CK Mapping | CTF5, CTF6 |
| Incident Report Writing | CTF5, CTF6 |

---

## Writeups

| CTF | Platform | Topic | Score | Report |
|---|---|---|---|---|
| CTF3 — Warlock | MYDFIR | Warlock Ransomware IR | - | [View](./ctf/warlock.md) |
| CTF6 — Akira | MYDFIR | Akira Ransomware IR · SPL + PCAP | **55/55 flags · 7th place** | [View](./ctf6-akira/CTF6_Writeup.md) |

---

## CTF6 Highlights — Kerning City Dental

> *Advanced · 55 flags · Akira ransomware full incident response*

**What I found:**
- Phishing email → ISO smuggling → DLL sideloading → UAC bypass via `fodhelper.exe`
- Credential theft via LSASS dump (`spoolsv.exe`, `0x1fffff`), AS-REP Roasting, ntdsutil AD dump
- Lateral movement via Pass-the-Hash (NTLM V2)
- Data exfiltration: `C:\Shares` → Mega.nz via rclone (masquerading as `MsMpEng.exe`)
- 1,184 Suricata alerts fired during exfiltration — unactioned
- 3 persistence mechanisms: scheduled task, registry Run key, backdoor domain admin account
- Full domain encrypted with Akira ransomware

**Attack chain:**
```
Phishing Email (Proton Mail)
    → ISO Mount → review.dll,StartW (rundll32)
        → fodhelper.exe UAC Bypass
            → taskhostw.exe (beacon) → C2: cdn.cloud-endpoint.net
                → LSASS Dump → Pass-the-Hash → Lateral Movement
                    → Data Exfil (rclone → Mega.nz)
                        → Shadow Copy Deletion
                            → Akira Ransomware
```

---

## Certifications & Training

- CompTIA Security+ *(in progress)*
- SC-900: Microsoft Security Fundamentals
- Cisco CyberOps Associate
- LetsDefend SOC Analyst Path
- MYDFIR CTF #6 — (55/55 flags)

---

*All IOCs in writeups are defanged. Lab environments only.*
