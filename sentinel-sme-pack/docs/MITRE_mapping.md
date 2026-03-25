# MITRE ATT&CK Mapping
## Microsoft Sentinel SME Detection Pack v1.0

| Rule ID | Rule Name | MITRE Tactic | MITRE Technique | Severity |
|---|---|---|---|---|
| IA-001 | Office App Spawning Suspicious Child | Initial Access | T1566.001 — Spearphishing Attachment | 🔴 High |
| IA-002 | Impossible Travel | Initial Access | T1078 — Valid Accounts | 🔴 High |
| IA-003 | Successful Login After Multiple Failures | Initial Access | T1110.001 — Password Guessing | 🔴 High |
| EX-001 | PowerShell Encoded Command | Execution | T1059.001 — PowerShell | 🔴 High |
| EX-002 | LOLBin Abuse | Execution | T1218 — System Binary Proxy Execution | 🟡 Medium |
| EX-003 | WMIC Spawning Suspicious Process | Execution | T1047 — WMI | 🔴 High |
| PE-001 | New Local Admin Account Created | Persistence | T1136.001 — Create Local Account | 🔴 High |
| PE-002 | Suspicious Scheduled Task | Persistence | T1053.005 — Scheduled Task | 🟡 Medium |
| PE-003 | Registry Run Key Modified | Persistence | T1547.001 — Registry Run Keys | 🟡 Medium |
| PR-001 | UAC Bypass via Fodhelper | Privilege Escalation | T1548.002 — Bypass UAC | 🔴 High |
| PR-002 | Token Impersonation Tools | Privilege Escalation | T1134.001 — Token Impersonation | 🔴 High |
| DE-001 | Event Log Cleared | Defense Evasion | T1070.001 — Clear Event Logs | 🔴 High |
| DE-002 | Windows Defender Tampered | Defense Evasion | T1562.001 — Disable Security Tools | 🔴 High |
| DE-003 | Process Masquerading | Defense Evasion | T1036.005 — Match Legitimate Name | 🟡 Medium |
| CA-001 | LSASS Credential Dumping | Credential Access | T1003.001 — LSASS Memory | 🔴 High |
| CA-002 | Password Spray Azure AD | Credential Access | T1110.003 — Password Spraying | 🔴 High |
| CA-003 | Kerberoasting Activity | Credential Access | T1558.003 — Kerberoasting | 🔴 High |
| LM-001 | Pass-the-Hash | Lateral Movement | T1550.002 — Pass the Hash | 🔴 High |
| LM-002 | Abnormal RDP Lateral Movement | Lateral Movement | T1021.001 — RDP | 🟡 Medium |
| LM-003 | SMB Admin Share Abuse | Lateral Movement | T1021.002 — SMB/Admin Shares | 🔴 High |
| EXFIL-001 | Large Outbound Data Transfer | Exfiltration | T1048 — Exfil Over Alt Protocol | 🟡 Medium |
| CC-001 | DNS Tunneling | Command & Control | T1071.004 — DNS | 🔴 High |
| CC-002 | C2 Beaconing | Command & Control | T1071.001 — Web Protocols | 🔴 High |

---

## Coverage Summary

| Tactic | Rules Covered | Coverage |
|---|---|---|
| Initial Access | 3 | Phishing, credential abuse, brute force |
| Execution | 3 | PowerShell, LOLBins, WMI |
| Persistence | 3 | Accounts, scheduled tasks, registry |
| Privilege Escalation | 2 | UAC bypass, token abuse |
| Defense Evasion | 3 | Log clearing, AV tamper, masquerading |
| Credential Access | 3 | LSASS, spray, Kerberoasting |
| Lateral Movement | 3 | PtH, RDP, SMB |
| Exfiltration | 1 | Large transfers |
| Command & Control | 2 | DNS tunnel, beaconing |
| **Total** | **23** | |

---

## MITRE ATT&CK Navigator Layer

Import the following into https://mitre-attack.github.io/attack-navigator/
to visualize your coverage:

The techniques covered in this pack highlight the most common attack paths
seen in SME breaches based on real-world incident data from 2023-2025.

**Most critical for SMEs (in order of frequency):**
1. T1566 — Phishing (still #1 initial access vector)
2. T1078 — Valid Accounts (credential compromise via spray/brute)
3. T1059 — Scripting (PowerShell abuse)
4. T1003 — Credential Dumping (post-compromise)
5. T1071 — C2 over common protocols (hard to detect without this pack)
