# Required Audit Policies
## Microsoft Sentinel SME Detection Pack

---

## Why This Matters

Windows does not log most security events by default. Without enabling the correct
audit policies, the Security Event log will be nearly empty and many rules in this
pack will generate zero alerts — not because threats aren't happening, but because
the telemetry isn't being collected.

This is one of the most commonly missed steps in SME Sentinel deployments.

---

## Option A — Group Policy (Recommended for AD environments)

Open Group Policy Management on your Domain Controller.
Edit the Default Domain Controllers Policy or create a new GPO.

Navigate to:
Computer Configuration > Windows Settings > Security Settings >
Advanced Audit Policy Configuration > Audit Policies

Enable the following:

### Account Logon
| Policy | Setting | Enables |
|---|---|---|
| Audit Credential Validation | Success + Failure | 4776 |
| Audit Kerberos Service Ticket Operations | Success + Failure | 4769 ← Kerberoasting rule |
| Audit Kerberos Authentication Service | Success + Failure | 4768 |

### Account Management
| Policy | Setting | Enables |
|---|---|---|
| Audit Security Group Management | Success | 4732 ← New admin account rule |
| Audit User Account Management | Success + Failure | 4720, 4740 ← New account rule |

### Logon/Logoff
| Policy | Setting | Enables |
|---|---|---|
| Audit Logon | Success + Failure | 4624, 4625 |
| Audit Other Logon/Logoff Events | Success + Failure | 4648 ← Explicit credentials |
| Audit Special Logon | Success | 4672 |

### Object Access
| Policy | Setting | Enables |
|---|---|---|
| Audit File Share | Success + Failure | 5140 ← SMB lateral movement rule |
| Audit Detailed File Share | Failure | 5145 |

### Process Tracking
| Policy | Setting | Enables |
|---|---|---|
| Audit Process Creation | Success | 4688 |

### Policy Change
| Policy | Setting | Enables |
|---|---|---|
| Audit Audit Policy Change | Success | 4719 |

### System
| Policy | Setting | Enables |
|---|---|---|
| Audit Security System Extension | Success | 4697 |
| Audit System Integrity | Success + Failure | 4612 |

### DS Access (Domain Controllers only)
| Policy | Setting | Enables |
|---|---|---|
| Audit Directory Service Changes | Success | 5136 |

Run this after changes to force immediate GPO update:
```
gpupdate /force
```

---

## Option B — Local Policy (Non-domain / workgroup environments)

Run on each machine, or push via Intune:

```powershell
# Enable all required audit policies
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable

# Verify settings applied
auditpol /get /category:*
```

---

## Option C — Microsoft Defender for Endpoint (MDE) environments

If you have MDE deployed, the DeviceProcessEvents, DeviceNetworkEvents,
and DeviceRegistryEvents tables are populated automatically.

You still need the Security Event log audit policies above for:
- Event ID 4624/4648 (logon events)
- Event ID 4720/4732 (account management)
- Event ID 5140 (file share access)
- Event ID 4769 (Kerberos tickets)

MDE does NOT replace the Windows Security Event log — both are needed.

---

## Verifying Collection in Sentinel

After enabling audit policies, run these queries in Sentinel Log Analytics
to confirm data is flowing:

```kql
// Check Security Events are being received
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count() by EventID
| order by count_ desc
```

```kql
// Check MDE tables are populated
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| summarize count() by DeviceName
| take 10
```

```kql
// Check Azure AD sign-in logs
SigninLogs
| where TimeGenerated > ago(1h)
| summarize count() by UserPrincipalName
| take 10
```

If any table returns 0 results, the corresponding connector is not configured.

---

## Common Issues

**SecurityEvent table is empty**
- Check that the "Security Events via AMA" connector is connected in Sentinel
- Verify the Data Collection Rule (DCR) is assigned to the correct machines
- Confirm audit policies are applied: `auditpol /get /category:*`

**DeviceProcessEvents is empty**
- MDE must be fully onboarded on the device
- MDE onboarding can take up to 24 hours to start populating tables

**SigninLogs is empty**
- Azure AD connector requires Global Admin or Security Admin role to connect
- Verify under Sentinel > Data connectors > Azure Active Directory > Status

**Event ID 5140 not appearing (SMB rule)**
- This requires Object Access auditing specifically for File Shares, not just Object Access
- Also verify the "Audit File Share" subcategory is enabled, not just the parent category
