# Deployment Guide
## Microsoft Sentinel SME Detection Pack v1.0

---

## Prerequisites

Before deploying these rules, ensure the following data connectors
are enabled in your Sentinel workspace:

### Required Connectors

**Microsoft Defender for Endpoint (MDE)**
- Enables: DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceFileEvents
- Setup: Sentinel → Data connectors → Microsoft Defender XDR → Connect

**Azure Active Directory**
- Enables: SigninLogs, AuditLogs
- Setup: Sentinel → Data connectors → Azure Active Directory → Connect

**Security Events via AMA**
- Enables: SecurityEvent (Event IDs 4624, 4648, 4698, 4720, 4732, 1102, etc.)
- Setup: Sentinel → Data connectors → Windows Security Events via AMA

**DNS (Optional but recommended for CC-001)**
- Enables: DnsEvents
- Setup: Sentinel → Data connectors → DNS (Preview)

---

## Deploying a Single Rule

1. Open **Microsoft Sentinel** in Azure Portal
2. Navigate to **Analytics** → **+ Create** → **Scheduled query rule**
3. Fill in the **General** tab:
   - Name: Use the Rule ID and name from the file (e.g., "CA-001 — LSASS Credential Dumping")
   - Description: Copy the description from the rule file
   - Severity: As documented in the rule
   - MITRE ATT&CK: Select the technique listed in the rule
4. Paste the **KQL query** in the Rule query field
5. Set **Query scheduling** as documented in each rule header
6. Configure **Alert threshold**: Generate alert when results > 0
7. Set **Entity mapping**:
   - Account → AccountName
   - Host → DeviceName or Computer
   - IP → IpAddress or RemoteIP
8. Review and **Save**

---

## Bulk Deployment via ARM Template (Advanced)

If you want to deploy all rules at once, convert each KQL to an
ARM template and deploy via Azure CLI:

```bash
az deployment group create \
  --resource-group <your-sentinel-rg> \
  --template-file sentinel_rules.json
```

Contact ismaelgatongg@gmail.com for assistance with bulk deployment.

---

## Recommended Workspace Settings

### Retention
Set data retention to minimum **90 days** for effective threat hunting.
Longer retention (1 year) is recommended for compliance environments.

### Workspace Auditing
Enable diagnostic settings on your Sentinel workspace to log
all query activity — important for audit trails.

### Alert Grouping
For high-volume rules (CA-002, EXFIL-001), enable alert grouping
to avoid alert fatigue:
- Group alerts into incidents: By entity (account, device)
- Grouping time window: 24 hours

---

## Testing Your Rules

Before going live, test each rule with known-good data:

```kql
// Quick test — check if the data source is returning data at all
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| summarize count() by FileName
| order by count_ desc
| take 10
```

If the table returns 0 results, your data connector is not working.

### Simulating Alerts (Safe Methods)
- **IA-003** — Intentionally fail 6 logins then succeed on a test account
- **PE-001** — Create a test local account in a lab VM
- **DE-001** — Clear the application log (not Security) on a test machine
- **CA-002** — Use a free IP from a different country + VPN on a test account

---

## Monitoring Rule Performance

After 30 days, review in **Sentinel → Analytics → Active rules**:
- Alerts generated per rule
- False positive rate (track via incident feedback)
- Mean time to close per alert

Target metrics for a healthy SME deployment:
- < 5 High severity alerts per day (anything more = too noisy)
- < 20 Medium severity alerts per day
- False positive rate < 70% within 60 days of tuning
