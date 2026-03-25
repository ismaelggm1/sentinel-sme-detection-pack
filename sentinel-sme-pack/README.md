# Microsoft Sentinel Detection Rule Pack for SMEs
### By Ismael Gaton | v1.0 | 2026
### Cybersecurity Professional — Microsoft & Capgemini | Security+, Google Cybersecurity

---

## About This Pack

Built and validated by a cybersecurity practitioner with hands-on experience in SOC
operations, incident response, and SIEM engineering at enterprise level (Microsoft,
Capgemini). Every rule reflects real-world detection logic used in production environments.

23 production-ready KQL detection rules for Microsoft Sentinel, built specifically
for Small and Medium Enterprises (SMEs). Each rule includes:

- Ready to deploy — paste directly into Sentinel Analytics
- MITRE ATT&CK mapped
- Plain-English explanation of what it detects and why it matters
- Tuning guidance based on real SOC experience
- Severity rating (High / Medium / Low)
- Response steps per tactic
- Customizable via top-level let variables — change thresholds in one place

---

## IMPORTANT — Read Before Deploying

Many rules depend on Windows audit policies that are DISABLED BY DEFAULT.
Without enabling them, the Event IDs will not appear in Sentinel.

See /docs/required_audit_policies.md for the full setup guide.

Policies that need enabling:
- Audit Logon Events          -> Event IDs 4624, 4648
- Audit Account Management    -> Event IDs 4720, 4732
- Audit Object Access (Share) -> Event ID 5140
- Audit Kerberos Svc Tickets  -> Event ID 4769

---

## Folder Structure

  /rules/
    /initial_access/        Phishing, credential abuse, impossible travel
    /execution/             Encoded PowerShell, LOLBins, WMI
    /persistence/           Scheduled tasks, registry, new admin accounts
    /privilege_escalation/  UAC bypass, token abuse
    /defense_evasion/       Log clearing, Defender tamper, masquerading
    /credential_access/     LSASS dumping, password spray, Kerberoasting
    /lateral_movement/      Pass-the-Hash, RDP abuse, SMB/PsExec
    /exfiltration/          Large transfers, DNS tunneling, C2 beaconing
  /tuning_guide/
    false_positive_guide.md
  /response_playbooks/
    playbooks_per_tactic.md
  /docs/
    MITRE_mapping.md
    deployment_guide.md
    required_audit_policies.md

---

## Required Data Connectors

Rule Category            | Connector                    | Table
-------------------------|------------------------------|---------------------------
Initial Access (cred)    | Azure Active Directory       | SigninLogs
Initial Access (phishing)| Microsoft Defender XDR       | DeviceProcessEvents
Execution                | Microsoft Defender XDR       | DeviceProcessEvents
Persistence              | Security Events via AMA + MDE| SecurityEvent, DeviceRegistryEvents
Credential Access        | Security Events via AMA + MDE| SecurityEvent, DeviceProcessEvents
Lateral Movement         | Security Events via AMA + MDE| SecurityEvent, DeviceNetworkEvents
Exfiltration             | Microsoft Defender XDR       | DeviceNetworkEvents
C2 / DNS Tunneling       | DNS (Preview)                | DnsEvents

---

## How to Deploy a Rule

1. Go to Microsoft Sentinel > Analytics > Create > Scheduled query rule
2. Copy the KQL from the rule file into the Rule query field
3. Set frequency and lookback period as documented in the rule header
4. Set alert threshold: Generate alert when results > 0
5. Configure entity mapping:
   - Account  -> AccountName or UserPrincipalName
   - Host     -> DeviceName or Computer
   - IP       -> IpAddress or RemoteIP
6. Save and enable

Full deployment walkthrough in /docs/deployment_guide.md

---

## Customization

Every rule has a CONFIGURATION block at the top with let variables.
Only change values in that block.

Example:
  let FailureThreshold = 5;   // Raise to 10 for large shared-NAT environments
  let LookbackWindow = 1h;    // Increase for wider detection window

---

## Severity Legend

  HIGH   - Respond within 15 minutes. Likely active threat.
  MEDIUM - Investigate within 4 hours. Suspicious but needs context.
  LOW    - Review daily. Informational or low-confidence signal.

---

## Support & Contact

Questions, customization, or bulk licensing:
ismaelgatongg@gmail.com
linkedin.com/in/ismaelgaton-32651a238
