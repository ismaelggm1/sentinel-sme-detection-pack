# False Positive Reduction Guide
## Microsoft Sentinel SME Detection Pack

---

## Why False Positives Happen

A false positive fires when a legitimate action matches a detection rule's pattern.
In SME environments, the most common causes are:

1. **Unmanaged software** — IT installs tools informally without documenting them
2. **Shared admin accounts** — multiple people using same account looks like spray/lateral movement
3. **Legacy applications** — old apps use insecure methods (NTLM, plain HTTP, RC4) legitimately
4. **RMM tools** — remote management software behaves like attackers (remote execution, file transfers)
5. **Backup agents** — access many files, make large transfers, run as SYSTEM

---

## Step-by-Step FP Reduction Process

### Phase 1 — Baselining (First 2 Weeks)
Run all rules in **observation mode** (alert only, no automated response):

1. Enable the rule with frequency set to every 4 hours
2. Let it run for 7-14 days
3. Review every alert — mark each as True Positive, False Positive, or Benign True Positive
4. Document the patterns of FPs:
   - Which account?
   - Which machine?
   - Which process?
   - What time of day?

### Phase 2 — Build Your Exclusion List
After baselining, create a shared KQL exclusion list you can reference across rules:

```kql
// Add to the top of any rule that needs exclusions
let KnownAdminAccounts = dynamic(["it_admin", "helpdesk_svc", "backup_agent"]);
let KnownRMMProcesses = dynamic(["connectwise.exe", "screenconnect.exe", "splashtop.exe", "anydesk.exe"]);
let KnownBackupProcesses = dynamic(["veeam.exe", "beremote.exe", "backupd.exe", "arcserve.exe"]);
let CorporateVPNIPs = dynamic(["x.x.x.x", "y.y.y.y"]);  // Replace with your VPN egress IPs
let CorporateOfficeCIDR = "x.x.x.0/24";  // Replace with your office IP range
```

### Phase 3 — Tune Thresholds
After 2 weeks you'll have data on normal behavior. Common adjustments:

| Rule | Common Adjustment |
|---|---|
| IA-003 Brute Force | Raise FailureThreshold from 5 to 10 for shared wifi envs |
| LM-002 RDP | Add IT helpdesk account exclusion |
| EXFIL-001 Large Transfer | Raise threshold if backup agent isn't excludable |
| CC-002 Beaconing | Add known update/telemetry processes |
| CA-002 Password Spray | Raise SprayThreshold for large NAT environments |

---

## Priority Order for New Deployments

Deploy rules in this order to minimize initial alert fatigue:

**Week 1 — High confidence, very low FP:**
- DE-001 (Log clearing)
- DE-003 (Process masquerading)
- CA-001 (LSASS dumping)
- PR-002 (Token abuse tools)

**Week 2 — Medium confidence, needs some tuning:**
- IA-001 (Office spawning cmd)
- EX-001 (Encoded PowerShell)
- PE-001 (New admin account)
- CA-003 (Kerberoasting)

**Week 3-4 — Context-dependent, needs baselining:**
- IA-002 (Impossible travel)
- IA-003 (Brute force success)
- LM-001 (Pass-the-hash)
- LM-002 (RDP lateral)
- CC-001 (DNS tunneling)
- CC-002 (Beaconing)

---

## Measuring Rule Quality

After 30 days, calculate the Signal-to-Noise ratio for each rule:

```
Signal-to-Noise = True Positives / (True Positives + False Positives)
```

Target: **> 0.3** (30% of alerts should be real or worthy of investigation)

If a rule is below 0.1 (less than 10% useful), either:
- Tune the thresholds more aggressively
- Add more exclusions
- Disable until you can baseline properly

---

## Common Environment-Specific Exclusions

### If you use Microsoft Intune / Endpoint Manager:
```kql
| where InitiatingProcessFileName !in~ ("intunemanagementextension.exe", "omadmclient.exe")
```

### If you use CrowdStrike Falcon:
```kql
| where InitiatingProcessFileName !in~ ("csagent.exe", "csfalconservice.exe", "falcond.exe")
```

### If you use SentinelOne:
```kql
| where InitiatingProcessFileName !in~ ("sentinelagent.exe", "sentinelone.exe")
```

### If you use a PSA/RMM tool (ConnectWise, Ninja, Datto):
```kql
| where InitiatingProcessFileName !in~ (
    "connectwisecontrol.clientservice.exe",
    "ninjarmm-agent.exe",
    "datto.rmm.agent.exe"
)
```
