# 🛡️ Microsoft Sentinel Detection Rule Pack for SMEs — v1.0

> **23 production-ready KQL detection rules** for Microsoft Sentinel, built specifically for Small and Medium Enterprises.
> Built and validated by a cybersecurity practitioner with hands-on SOC and IR experience at Microsoft and Capgemini.

---

## 📦 What's in the Full Pack

| Category | Rules | Key Threats Covered |
|---|---|---|
| Initial Access | 3 | Phishing, impossible travel, brute force |
| Execution | 3 | Encoded PowerShell, LOLBins, WMI abuse |
| Persistence | 3 | New admin accounts, scheduled tasks, registry |
| Privilege Escalation | 2 | UAC bypass, token impersonation |
| Defense Evasion | 3 | Log clearing, Defender tamper, masquerading |
| Credential Access | 3 | LSASS dumping, password spray, Kerberoasting |
| Lateral Movement | 3 | Pass-the-Hash, RDP abuse, SMB/PsExec |
| Exfiltration + C2 | 3 | Large transfers, DNS tunneling, beaconing |

Every rule includes:
- ✅ MITRE ATT&CK mapping
- ✅ Plain-English explanation
- ✅ `let` variable config block — change thresholds in one place
- ✅ Tuning notes from real SOC experience
- ✅ Response steps

---

## 🆓 Free Sample Rules

### SAMPLE 1 — Encoded PowerShell Detection
**MITRE:** T1059.001 | **Severity:** 🔴 High

```kql
// Detects PowerShell launched with encoded commands
// Attackers encode payloads to evade basic string detection
// Legitimate encoded PS in SME environments is extremely rare

DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "-ec ")
| extend IsBase64 = ProcessCommandLine matches regex @"[A-Za-z0-9+/]{50,}={0,2}"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, FolderPath
```

> **Tuning:** Exclude known RMM tools (ConnectWise, N-able) by InitiatingProcessFileName if they cause FPs. To decode the payload: CyberChef → From Base64 → UTF-16LE.

---

### SAMPLE 2 — Impossible Travel (Same Account, Two Countries)
**MITRE:** T1078 | **Severity:** 🔴 High

```kql
// Detects same user signing in from two different countries
// in a timeframe that's physically impossible for travel.
// Classic indicator of credential compromise in M365 environments.

SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == 0
| where isnotempty(LocationDetails)
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize
    Countries = make_set(Country),
    IPs = make_set(IPAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, AppDisplayName
| where array_length(Countries) > 1
| extend TimeDiffMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project FirstSeen, LastSeen, TimeDiffMinutes, UserPrincipalName,
    AppDisplayName, Countries, IPs
```

> **Tuning:** Exclude known corporate VPN egress IPs to reduce FPs from remote workers.

---

### SAMPLE 3 — Windows Defender Tampered or Disabled
**MITRE:** T1562.001 | **Severity:** 🔴 High

```kql
// Detects attempts to disable Defender via PowerShell, SC.exe, or registry.
// Malware disables AV before executing its payload.
// In SMEs without a separate EDR, Defender is often the last line of defense.

DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "Set-MpPreference -DisableRealtimeMonitoring $true",
    "Set-MpPreference -DisableIOAVProtection $true",
    "DisableAntiSpyware",
    "Add-MpPreference -ExclusionPath"
)
| project TimeGenerated, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

---

### SAMPLE 4 — New Local Admin Account Created
**MITRE:** T1136.001 | **Severity:** 🔴 High

```kql
// Detects a new local user account created and added to Administrators.
// Classic persistence backdoor — almost never legitimate in SMEs.
// Requires: Audit Account Management enabled in GPO.

let AccountCreation = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4720
| project TimeGenerated, Computer, SubjectUserName, TargetUserName;

let AddedToAdmins = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4732
| where TargetUserName =~ "Administrators"
| project TimeGenerated, Computer, SubjectUserName, MemberName;

AccountCreation
| join kind=inner (AddedToAdmins) on Computer
| project TimeGenerated, Computer, SubjectUserName, TargetUserName
```

---

### SAMPLE 5 — Security Event Log Cleared
**MITRE:** T1070.001 | **Severity:** 🔴 High

```kql
// Detects the Security or System event log being cleared.
// Almost always an attacker covering their tracks.
// Extremely low false positive rate — almost never a legitimate action.

SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (1102, 104)
| project TimeGenerated, Computer, AccountName, Activity, EventID
```

---

## 💰 Get the Full Pack (23 Rules + Docs)

**[→ Buy on Gumroad]((https://ismaelggm.gumroad.com/l/lhteh))** — €39

Includes all 23 rules + MITRE mapping + deployment guide + audit policy setup + FP reduction guide + 5 incident response playbooks.

---

## 👤 About the Author

Cybersecurity professional with hands-on experience in SOC operations, incident response, and SIEM engineering at **Microsoft** and **Capgemini**. Certified: CompTIA Security+, Google Cybersecurity Professional.

- 🔗 [LinkedIn](https://www.linkedin.com/in/ismaelgaton-32651a238/)
- 📧 ismaelgatongg@gmail.com
- 🔍 [TryHackMe](https://tryhackme.com/p/ismaelggm)

---

## ⚠️ Disclaimer

These rules are provided for defensive security purposes only. Always test in a non-production environment before deploying. Validate rules match your environment's field formats before enabling automated response actions.
