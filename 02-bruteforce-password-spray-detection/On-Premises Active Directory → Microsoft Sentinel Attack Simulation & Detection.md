---
Created: 2026-09-21
tags:
  - active-directory
  - PasswordSpraying
  - Detection
  - SIEM
  - Azure
  - Windows
---
## Objective 

Build a hybrid SOC detection pipeline that streams Windows Security telemetry from an on-premises Active Directory [[Domain Controller]] into Microsoft Sentinel, then simulate a real credential attack from an attacker host and detect it with a custom KQL analytics rule that raises a MITRE-mapped incident.

The value of this build is that the domain controller stays **on-premises** and is projected into the cloud SIEM via Azure Arc — a hybrid pattern that mirrors how most real enterprises actually monitor legacy infrastructure, rather than running everything natively in Azure.


## Architecture 

```plain text
Kali (attacker) — 192.168.100.50
        │   SMB password spray (NetExec)
        ▼
Windows Server 2022 DC — zeroDae.local (192.168.100.10)
        │   Event ID 4625 (failed network logons)
        ▼
Azure Arc + Azure Monitor Agent (AMA)
        │   Data Collection Rule (dcr-dc-securityevents)
        ▼
Log Analytics Workspace — law-zerodae
        ▼
Microsoft Sentinel — KQL analytics rule → Incident
```


# Attack Simulation — Password Spray and Password Guessing

### Spray vs. Guessing

Password spraying and password guessing are cousins that fall under the same MITRE ATT&CK mapping of Credential Access → T1110 (Brute Force).

**Password spraying** (one password × many users) works by attempting a single password against a large set of valid user accounts. The attacker keeps the attempts per account below the lockout threshold — three in this environment. That number varies with the organization's password policy; this method helps avoid locking accounts and drawing attention. Because the attack touches many accounts at once, every targeted account should be **reviewed** and **secured** immediately.

**Password guessing** (one user × many passwords) is closer to a traditional brute-force approach, which makes it loud and easy to spot. It usually means a single enterprise account is being targeted directly, and that account should be quarantined until the activity is investigated.

### Password Spraying - T1110.003

I created six disposable domain accounts as targets, then ran a **password spray** with NetExec — one incorrect password tried against all six accounts. Spraying (one password × many users) generates a burst of failed logons from a single source without exceeding the 3-attempt account-lockout threshold on any individual account.
	![13-nxc-spray.png](Images/13-nxc-spray.png)
	
```bash
# Target list
echo -e "sprayuser1\nsprayuser2\nsprayuser3\nsprayuser4\nsprayuser5\nsprayuser6" > users.txt

# Spray one wrong password across all six accounts
nxc smb 192.168.100.10 -u users.txt -p 'Wrong-Password-123!' -d zeroDae.local --continue-on-success
```

## Attack Telemetry in Sentinel

The six failed logons appeared in the `SecurityEvent` table within seconds, each stamped with the attacker's source IP (`192.168.100.50`) and **LogonType 3** (network / SMB) — the fingerprint of a remote credential attack.
	![10-4625-events.png](Images/10-4625-events.png)
	![10-4625-events-2.png](Images/10-4625-events-2.png)
	
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(30m)
| project TimeGenerated, TargetAccount, IpAddress, WorkstationName, LogonType
| order by TimeGenerated desc
```



# Writing a Scheduled Analytics Rule for Brute-Force Detection in KQL

An analytics rule is, in short, comparable to a security camera for the SOC team. The one referenced here is a **Scheduled rule** — it continuously monitors log data for the events matched by its query.

This is one of the first steps in the detection phase for a SOC analyst, who will then investigate and determine whether the alert is a false positive.

### Creating a Rule

1. Navigate to **Microsoft Sentinel → Analytics → Create → Scheduled query rule**.
2. Name the **Analytics rule** (`Brute Force – Multiple Failed Logons (4625)`)
   ![sentinel-rule-edit-general.png](Images/sentinel-rule-edit-general.png)

4. Set the Severity level (`Medium`) → set the MITRE ATT&CK tactic (`Credential Access`)
   ![sentinel-rule-edit-mitre-attack.png](Images/sentinel-rule-edit-mitre-attack.png)

6. Click `Next: Set rule logic` → add the custom query.
   ![sentinel-4625-password-spray-query.png](Images/sentinel-4625-password-spray-query.png])
   ![sentinel-rule-wizard-query-scheduling.png](Images/sentinel-rule-wizard-query-scheduling.png)

8. Specify the Entity mapping.
	- Account: `Name = TargetedAccounts`
		- Gives Sentinel additional context for the alert, correlating real-world entities such as users and IP addresses.
	![sentinel-rule-edit-entity-mapping.png](Images/sentinel-rule-edit-entity-mapping.png)

9. Verify "Create incidents from alerts triggered by this analytics rule" is enabled in the **Incident settings**.
    ![sentinel-rule-edit-incident-settings.png](Images/sentinel-rule-edit-incident-settings.png)
	![sentinel-rule-wizard-automated-response.png](Images/sentinel-rule-wizard-automated-response.png)

11. Click **Review & Create**.
    ![sentinel-rule-wizard-review-create.png](Images/sentinel-rule-wizard-review-create.png)

The rule is now live in the Analytics **Active rules** list, alongside the SPN Honeypot and Kerberoasting rules:
![sentinel-analytics-3-rules-dup.png](Images/sentinel-analytics-3-rules-dup.png)

## Scheduled Analytics Rule → Incident

| Setting           | Value                                                               |
| ----------------- | ------------------------------------------------------------------- |
| Name              | Brute Force – Multiple Failed Logons (4625)                         |
| Severity          | Medium                                                              |
| MITRE ATT&CK      | Credential Access → **T1110 (Brute Force)** — observed as .001 Guessing & .003 Spraying |
| Entity mapping    | IP → `IpAddress` · Account → `TargetedAccounts` · Host → `Computer` |
| Schedule          | Run every 5 minutes · 1-hour lookback                               |
| Incident creation | Enabled (grouped alerts)                                            |

#### Rule A - Brute Force: Multiple Failed Logons Detection Rule (T1110)

- Description: Detecting multiple failed user sign-in attempts within a specific timeframe ([[Event ID 4625|4625]]).
- MITRE ATT&CK: expand **Credential Access** → check **Brute Force (T1110)** — the demos exercise Password Guessing (.001) and Password Spraying (.003).
	
```KQL
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count(),
            TargetedAccounts = make_set(TargetAccount, 50),
            StartTime = min(TimeGenerated),
            EndTime = max(TimeGenerated)
    by IpAddress, Computer
| where FailedAttempts >= 5
```

- Entity Mapping: 
	- IP = `192.168.100.50`
	- Host = `WIN-PLG4VMVBU6A`

- **Breakdown**:
	- `SecurityEvent` — start with the table that holds all the Windows security logs from my DC.
	- `where EventID == 4625` — keep only the "a logon failed" events. (4625 = failed sign-in.) Throw everything else away.
	- `summarize FailedAttempts = count()` — group the failures into buckets — one bucket per source IP + machine combo. For each bucket, calculate the summary values above.
	- `TargetedAccounts = make_set(TargetAccount, 50)` — make a list (up to 50) of the distinct usernames that were targeted from that IP — so I can see _which_ accounts were sprayed.
	- `StartTime = min(TimeGenerated)` — the timestamp of the first failure in the bucket (when the attack started).
	- `EndTime = max(TimeGenerated)` — the timestamp of the last failure (when it ended) — using the start and end time together shows the attack window.
	- `where FailedAttempts >= 5` — now that failures are counted per source, keep only sources with 5 or more. One or two failures is a fat-fingered password; a burst from one IP against many accounts is a spray.

#### Incident Feedback

**Attack VM POV — credential guessing against `Yuji.Itadori`:**
	
![nxc-password-guessing-yuji.png](Images/nxc-password-guessing-yuji.png)
	
```bash
nxc smb 192.168.100.10 -u Yuji.Itadori -p password.list -d zeroDae.local
```

**Incident queue:** on the left-side menu of the control panel you'll find the Incidents tab, where any incidents that have occurred are generated.
- Each created rule generates an incident when all its conditions are met.
![incident-list-password-spraying.png](Images/incident-list-password-spraying.png)

**Attack story / entity graph:** the attack story is a visual, node-based map that displays the full spread and chronology of the attack. Since the only thing targeted was one valid user and the attack failed (no password hits), there is no other data indicating the attacker gained credentials or laterally moved.
	
![incident-3-attack-story.png](Images/incident-3-attack-story.png)

**Evidence — alert query results:**
![incident-3-query-results.png](Images/incident-3-query-results.png)

**Activity log — automatic correlation:**
![incident-3-activity-correlation.png](Images/incident-3-activity-correlation.png)

## Skills Demonstrated

- **Hybrid cloud log pipeline** — projecting an on-prem AD DC into a cloud SIEM with Azure Arc + Azure Monitor Agent + Data Collection Rules
- **Detection engineering** — writing and tuning a KQL analytics rule with entity mapping
- **Attack simulation** — password spraying and password guessing with NetExec against a live domain controller
- **MITRE ATT&CK mapping** — classifying the detection as T1110 (Brute Force), covering .001 (Guessing) and .003 (Spraying)
- **SOC analyst workflow** — the full loop of attack → telemetry → detection → incident
