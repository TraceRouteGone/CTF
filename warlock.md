# Incident Report: Warlock Ransomware Attack

**FROM:** MahCyberDefense SOC Team  
**TO:** Richard Oakley  
**DATE:** January 16, 2026  
**PRIORITY:** CRITICAL  

---

## 1. Executive Summary

On 14 January 2026, VHR was targeted by a human-operated ransomware attack (Warlock) that resulted in full domain compromise, exfiltration of sensitive data, and enterprise-wide encryption. The attack began when a contractor executed a phishing attachment (`NHS_Spine_Certificate_Tool.exe`), allowing the adversary to escalate privileges and compromise core infrastructure, including the domain controller and backup systems.  

- **Impact:** Business operations halted due to encrypted file shares and backups; privileged credentials fully compromised.  
- **Current Status:**  
  - Containment: No further execution of `warlock.exe` observed after 21:33 UTC; compromised hosts isolated (`VHR-WS-1`, `VHR-DC01`, `VHR-BACKUP`).  
  - Credential Compromise: `svc_backup` and `helpdesk` accounts fully compromised.  
  - Backup Status: Local backups and shadow copies destroyed; restoration depends on secure off-site backups.  
  - Security Controls: Defender protections disabled; persistent tasks and encrypted tunnels detected.  

**Immediate Action Required:** Reset all privileged credentials and verify containment before restoring services.

---

## 2. Findings

### 2.1 Initial Access & Execution
- **Method:** Spear-phishing (T1566.001)  
- **User:** `VHR\j.wilson`  
- **Host:** `VHR-WS-1`  
- **Activity:** Execution of `NHS_Spine_Certificate_Tool.exe` triggered a fileless PowerShell loader, establishing an initial foothold.  
- Secondary execution by `helpdesk` account indicates lateral movement.  

**Persistence & C2:**  
- Scheduled Task `NHSSpineSync` ensures malware runs at logon.  
- Encrypted tunnels via VS Code (`code.exe`) and Cloudflared maintained C2.  

**Credential Access & Privilege Escalation:**  
- Compromised `helpdesk` account → Kerberoasting on `svc_backup`.  
- Offline password cracking revealed plaintext: `Backup2024!`.  

**Lateral Movement & Discovery:**  
- Access to `VHR-DC01` (Domain Controller) and `VHR-BACKUP`.  
- Reconnaissance of AD, shares, backup directories.  

**Data Collection & Exfiltration:**  
- Staging of sensitive data in `C:\Windows\Temp\exfil\loot.zip`.  
- Exfiltration via encrypted outbound tunnels.  

**Defense Evasion:**  
- Disabled Defender, deleted shadow copies, stopped critical services (`SQL`, `VSS`).  

**Impact:**  
- Loss of enterprise file availability (`C:\Shares`, `D:\Backups`)  
- Backup encryption, domain-level compromise.  

---

## 3. Recommendations

### Immediate (0–24 hours)
- Reset all Domain Admin and Service account passwords.  
- Decommission `svc_backup` and replace with gMSA.  
- Keep affected servers offline until verified clean.  
- Block outbound tunneling domains at firewall.  

### Short-term (1–7 days)
- Restore data from verified off-site or immutable backups.  
- Enforce strong passwords (≥25 characters) for service accounts.  

### Long-term (30–90 days)
- Require MFA for all administrative accounts.  
- Network segmentation for backup infrastructure.  

---

## 4. Appendix – Evidence Summary

### 4.1 Initial Access – Execution of Malicious Payload
**Objective:** Identify entry point.  
**Finding:** Contractor `j.wilson` executed phishing binary; lateral movement by `helpdesk`.  

**Timeline:**  
| Time (UTC) | Host | Activity |
|------------|------|---------|
| 19:38:13 | VHR-WS-1 | `j.wilson` executes payload |
| 19:46:49 | VHR-WS-1 | `helpdesk` executes payload |

**Screenshots:**  
![Screenshot 4.1a](ctf/4.1-1.png)  
![Screenshot 4.1b](ctf/4.1-2.png)  

---

### 4.2 Persistence – Scheduled Task Creation
**Objective:** Ensure ongoing access.  

**Timeline:**  
| Time (UTC) | Host | Activity |
|------------|------|---------|
| 20:03:24 | VHR-WS-1 | `NHSSpineSync` task created |

**Screenshots:**  
![Screenshot 4.2](ctf/4.2.png)  

---

### 4.3 Lateral Movement – Access to Domain Controller
**Timeline:**  
| Time (UTC) | Host | Activity |
|------------|------|---------|
| 20:33:57 | VHR-DC01 | `svc_backup` network logon |
| 20:34:39 | VHR-BACKUP | `svc_backup` network logon |

**Screenshots:**  
![Screenshot 4.3](ctf/4.3.png)  

---

### 4.4 Data Staging Activity
**Timeline:**  
| Time (UTC) | Host | Activity |
|------------|------|---------|
| 21:10–21:20 | VHR-DC01 | Data staged and compressed into `loot.zip` |

**Screenshots:**  
![Screenshot 4.4](ctf/4.4.png)  

---

### 4.5 Command & Control – Encrypted Tunneling Tools
**Timeline:**  
| Time (UTC) | Host | Activity |
|------------|------|---------|
| 20:12:00 | VHR-WS-1 | `code.exe` tunnel executed, Cloudflared installed |

**Screenshots:**  
![Screenshot 4.5](ctf/4.5.png)  

---

### 4.6 Defense Evasion – vssadmin delete shadows
**Timeline:**  
| Time (UTC) | Host | Activity |
|------------|------|---------|
| 21:20:15 | VHR-DC01 | Shadow copies deleted |

**Screenshots:**  
![Screenshot 4.6](ctf/4.6.png)  

---

### 4.7 Ransomware Execution – warlock.exe
**Timeline:**  
| Time (UTC) | Host | Activity |
|------------|------|---------|
| 21:26:37 | VHR-DC01 | `warlock.exe` executed |
| 21:27:47 | VHR-BACKUP | `warlock.exe` executed |
| 21:29:16 | VHR-WS-1 | `warlock.exe` spread |

**Screenshots:**  
![Screenshot 4.7](ctf/4.7.png)  

---

### 4.8 Discovery – Domain Enumeration & Target Identification
**Timeline:**  
| Time (UTC) | Host | Activity |
|------------|------|---------|
| 21:33:05 | VHR-DC01 | Aggressive enumeration of VHR.local |

**Screenshots:**  
![Screenshot 4.8](ctf/4.8.png)  

---

## 5. Timeline (Summary)

| Time (UTC) | Host | Activity |
|------------|------|---------|
| 19:38:13 | VHR-WS-1 | Initial Access |
| 19:46:49 | VHR-WS-1 | Privilege Escalation |
| 20:03:24 | VHR-WS-1 | Persistence Established |
| 20:10:18 | VHR-WS-1 | Downloaded `code.zip` |
| 20:12:00 | VHR-WS-1 | Encrypted C2 Channel |
| 20:29:30 | VHR-WS-1 | Privilege Enumeration |
| 20:30:02 | VHR-WS-1 | Domain Controller Discovery |
| 20:33:57 | VHR-DC01 | Lateral Movement |
| 20:34:39 | VHR-BACKUP | Backup Infrastructure Compromise |
| 21:10:45 | VHR-DC01 | Data Staging |
| 21:20:15 | VHR-DC01 | Shadow Copies Destroyed |
| 21:26:37 | VHR-DC01 | Ransomware Deployment Begins |
| 21:27:47 | VHR-BACKUP | Ransomware executed |
| 21:29:16 | VHR-WS-1 | Ransomware spreads |
| 21:33:05 | VHR-DC01 | Enumeration / Discovery |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique Name | Technique ID | Observed Activity |
|--------|----------------|-------------|-----------------|
| Initial Access | Phishing | T1566.001 | Payload executed by `j.wilson` |
| Execution | User Execution: Malicious File | T1204.002 | User ran phishing binary |
| Persistence | Scheduled Task | T1053.005 | `NHSSpineSync` task created |
| Privilege Escalation | Valid Accounts | T1078.002 | `svc_backup` used for DC & Backup |
| Defense Evasion | Inhibit System Recovery | T1490 | Shadow copies deleted |
| Discovery | Account Discovery | T1087.002 | `net group "Domain Admins"` |
| Discovery | Remote System Discovery | T1018 | `nltest /dclist` |
| Lateral Movement | SMB / Admin Shares | T1021.002 | Network logon Type 3 to DC & Backup |
| Collection | Archive via Utility | T1560.001 | Data zipped in `Temp\exfil\loot.zip` |
| Command & Control | Protocol Tunneling | T1572 | VS Code Tunnel used for C2 |
| Impact | Data Encrypted | T1486 | `warlock.exe` deployed enterprise-wide |

---

## 7. IOC List (Indicators of Compromise)

**Network Indicators**

| Type | Indicator | Description |
|------|-----------|-------------|
| IP Address | 192.168.50.6 | Source host for lateral movement |
| Domain | sync.cloud-endpoint[.]net | External second-stage payload |
| Domain | *.relay.tunnels.api.visualstudio[.]com | VS Code Tunnel relay |
| Domain | *.cloudflare-gateway[.]com | Cloudflared outbound |

**Host-Based Indicators**

| Type | Indicator | Description |
|------|-----------|-------------|
| File Path | `*\NHS_Spine_Certificate_Tool.exe` | Initial phishing payload |
| File Path | `C:\Windows\Temp\code.exe` | VS Code binary for C2 |
| File Path | `C:\Windows\Temp\warlock.exe` | Ransomware executable |
| File Path | `C:\Windows\Temp\exfil\loot.zip` | Staged enterprise data |
| Scheduled Task | `NHSSpineSync` | Persistence task |
| Registry Key | `HKLM\Software\Microsoft\Windows Defender\DisableAntiSpyware = 1` | Defender disabled |
| Registry Key | `HKLM\Software\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 1` | Real-time monitoring disabled |
| Utility/Command | `vssadmin.exe delete shadows` | Shadow copies deleted |

---

*End of Incident Report*
