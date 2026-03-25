# Incident Response Playbooks
## Per MITRE Tactic — Microsoft Sentinel SME Pack

---

## How to Use These Playbooks

Each playbook is a step-by-step response guide for when one of the
detection rules fires. Steps are ordered by priority.

**Severity guide:**
- 🔴 High → Start response within 15 minutes
- 🟡 Medium → Investigate within 4 hours
- 🟢 Low → Review next business day

---

## PLAYBOOK 1 — Credential Compromise
**Triggered by:** IA-002, IA-003, CA-002

### Immediate (0-15 min)
- [ ] Identify the affected user account (UserPrincipalName)
- [ ] Check if the suspicious login created any mail rules or forwarding
  - Azure AD → User → Mail settings → Forwarding
- [ ] Check what applications were accessed after the suspicious login
  - SigninLogs → filter by UserPrincipalName → sort by TimeGenerated

### Containment (15-60 min)
- [ ] Force sign-out of all sessions:
  - Azure AD → User → Revoke sessions
- [ ] Reset the user's password (use temporary password, force change on login)
- [ ] If MFA is not enabled → ENABLE IT NOW
- [ ] Block the source IP via Conditional Access if it's clearly malicious

### Investigation (1-4 hrs)
- [ ] Check for new inbox rules created by the attacker:
  ```kql
  OfficeActivity
  | where Operation == "New-InboxRule"
  | where UserId == "<compromised_user>"
  | where TimeGenerated > ago(7d)
  ```
- [ ] Check for emails forwarded externally
- [ ] Check if any files were accessed or downloaded via SharePoint/OneDrive
- [ ] Look for MFA registration changes (new phone/authenticator added)

### Post-Incident
- [ ] Notify the user and explain what happened
- [ ] Document timeline in your incident log
- [ ] Review Conditional Access policies — consider requiring MFA from all locations

---

## PLAYBOOK 2 — Active Malware / Post-Exploitation
**Triggered by:** IA-001, EX-001, EX-002, CA-001, DE-002, DE-003

### Immediate (0-15 min)
- [ ] **ISOLATE THE DEVICE** via Microsoft Defender for Endpoint:
  - MDE Portal → Device inventory → Select device → Isolate device
- [ ] Document the device name, user, and exact time of alert
- [ ] Do NOT touch the device or allow the user to use it

### Containment (15-30 min)
- [ ] Collect live response data before remediation:
  - MDE → Device → Live Response
  - Run: `processes` to see running processes
  - Run: `connections` to see active network connections
  - Run: `getfile <suspicious_file_path>` to collect samples
- [ ] Block the malicious file hash across the org:
  - MDE → Indicators → Add file hash → Block

### Investigation (30 min - 4 hrs)
- [ ] Check what ran BEFORE the alert (10-30 min window):
  ```kql
  DeviceProcessEvents
  | where DeviceName == "<affected_device>"
  | where TimeGenerated between(ago(2h) .. now())
  | order by TimeGenerated asc
  ```
- [ ] Check for lateral movement FROM this device:
  ```kql
  DeviceNetworkEvents
  | where DeviceName == "<affected_device>"
  | where RemoteIPType != "Loopback"
  | where TimeGenerated > ago(24h)
  ```
- [ ] Check for persistence mechanisms added:
  - New scheduled tasks (Event ID 4698)
  - New registry run keys
  - New local accounts (Event ID 4720)
- [ ] Hash any dropped files and submit to VirusTotal

### Remediation
- [ ] Reimage the device — do NOT attempt to clean malware manually in SME environments
- [ ] Reset credentials for the affected user AND any accounts that were logged into that device
- [ ] Check all devices the user regularly accesses — expand scope if needed

---

## PLAYBOOK 3 — Lateral Movement Detected
**Triggered by:** LM-001, LM-002, LM-003

### Immediate (0-15 min)
- [ ] Identify SOURCE device (where movement originated FROM)
- [ ] Identify TARGET devices (where movement went TO)
- [ ] Isolate SOURCE device immediately via MDE

### Containment
- [ ] Block the affected account from authenticating:
  - Azure AD → User → Disable account (temporary)
- [ ] Isolate TARGET devices if evidence of execution on them
- [ ] Block NTLM authentication at the firewall between workstations if possible

### Investigation
- [ ] Determine the initial compromise vector on the SOURCE device
  - When was the source device first compromised?
  - What ran before the lateral movement?
- [ ] For each TARGET device, check:
  - Were any new processes launched via the lateral movement?
  - Were any persistence mechanisms installed?
  - Were any credentials accessed?
- [ ] Map the full attack path:
  ```
  [Initial Access Vector] → [Source Device] → [Target Device(s)]
  ```

### Remediation
- [ ] Scope: Assume ALL devices accessed via lateral movement are compromised
- [ ] Reset credentials for the account used in lateral movement
- [ ] Reimage all compromised devices
- [ ] Review network segmentation — workstations should not be able to
  communicate directly with each other in a well-segmented network

---

## PLAYBOOK 4 — Persistence Detected
**Triggered by:** PE-001, PE-002, PE-003

### Immediate
- [ ] Identify the persistence mechanism type (account / scheduled task / registry)
- [ ] Remove the persistence mechanism:
  - **Account:** Disable and delete the account
  - **Scheduled task:** Delete via Task Scheduler or: `schtasks /delete /tn "<taskname>"`
  - **Registry:** Delete the registry value

### Investigation
- [ ] Check if the persistence mechanism already executed:
  - Look for the scheduled task's process in DeviceProcessEvents
  - Check registry value data — what executable does it point to?
- [ ] Hash any referenced executables and check VirusTotal
- [ ] Look for additional persistence mechanisms — attackers often set multiple

### Key Question
**Did the attacker already achieve their objective, or are they still in the environment?**
Check for exfiltration and C2 indicators before concluding.

---

## PLAYBOOK 5 — Exfiltration / C2 Activity
**Triggered by:** EXFIL-001, CC-001, CC-002

### Immediate
- [ ] Block the destination IP/domain at the firewall immediately
- [ ] Identify the device making the outbound connection
- [ ] Check how long this has been happening:
  ```kql
  DeviceNetworkEvents
  | where RemoteIP == "<c2_ip>"
  | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Count=count()
  ```

### Containment
- [ ] Isolate the device via MDE
- [ ] If DNS tunneling: Block the destination domain at DNS level (not just firewall)
- [ ] Check for the same destination across ALL devices in your environment

### Investigation
- [ ] Estimate what data may have been exfiltrated:
  - What files did the process access? (DeviceFileEvents)
  - How many bytes were sent total?
  - Was sensitive data (finance, HR, customer data) accessible from that device?
- [ ] Determine if this is ransomware pre-staging or espionage

### Notification Considerations
If sensitive data was exfiltrated, you may have **GDPR notification obligations**:
- EU: 72-hour notification to supervisory authority
- Consult your DPO or legal counsel immediately
