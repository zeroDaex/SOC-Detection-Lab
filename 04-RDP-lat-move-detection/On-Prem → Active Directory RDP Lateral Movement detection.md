# RDP Lateral Movement: Stolen-Credential Remote Logon, Attack & Detection (Microsoft Sentinel)

**Author:** zeroDae
**Date:** September 2026
**MITRE ATT&CK:** T1021.001 — Lateral Movement → Remote Services: Remote Desktop Protocol · T1078 — Valid Accounts

---

## Objective

Demonstrate the full stolen-credential RDP lateral-movement path against an on-premises Active Directory domain controller and detect the interactive remote logon in Microsoft Sentinel. I take a single valid domain credential, use it to enumerate the domain over SMB, gain a Remote Desktop session on the DC with `xfreerdp`, and detect the RemoteInteractive logon via Event ID 4624 (LogonType 10).

This builds directly on the on-prem DC → Azure Arc → AMA → Sentinel pipeline established in the earlier projects; that telemetry path (the `Audit Logon` policy, Event IDs 4624 / 4625) is already live, so this project focuses on the attack and the RDP-specific detection.

---

## Why RDP Lateral Movement Matters

RDP abuse is *living-off-the-land*: the attacker isn't dropping malware, they're using a valid account and a built-in Windows service (Remote Desktop) the way a real admin would. Once one credential is compromised, RDP turns that credential into a full interactive desktop on the target. Because the traffic and the logon look legitimate, it blends into normal administrative activity, which is exactly what makes it dangerous and why detection has to lean on *context* (who, from where, what logon type) rather than on a signature.

---

## Environment

| Component | Detail |
|---|---|
| Domain Controller | Windows Server 2022 · `WIN-PLG4VMVBU6A` · domain `zeroDae.local` (192.168.100.10) |
| Attacker | Kali Linux (192.168.100.50, Internal Network) |
| SIEM | Microsoft Sentinel · Log Analytics `law-zerodae` |
| Compromised credential | `Yuji.Itadori` — valid domain user (`test123!`) used as the foothold account |

---

## Account Setup

The scenario starts from a single valid domain credential for the user `Yuji.Itadori` — this is treated as the foothold an attacker would already hold after phishing, spraying, or a prior roast.

Set (or confirm) the account used for this run:

![[set-domain-user-password-yuji.png]]
*Figure 1 — Setting the domain password for the foothold account `Yuji.Itadori`.*

```powershell
net user Yuji.Itadori 'test123!' /domain
```

Enumerating the domain's user accounts confirms the account exists alongside the rest of the directory:

![[net-user-domain-accounts-list.png]]
*Figure 2 — `net user` listing the domain accounts on the DC.*

I also pointed my Kali resolver at the DC so domain name resolution works:

![[kali-resolv-conf-dns.png]]
*Figure 3 — `/etc/resolv.conf` pointing DNS at the DC (192.168.100.10).*

#### Enable the RDP Path / Grant Logon Rights

A valid credential alone doesn't grant a remote desktop — the account also needs the **Allow log on through Remote Desktop Services** right, and RDP has to be enabled on the target. This is the step that turns "I have a password" into "I have a session."

- Enable Remote Desktop on the target and add the account to Remote Desktop Users:
	![[Enabling-RDP.png]]
	*Figure 4 — Enabling Remote Desktop on the target.*
	![[Assining-User-RDP.png]]
	*Figure 5 — Assigning the account Remote Desktop access.*

- Confirm the user right locally (Local Security Policy → User Rights Assignment):
	![[secpol-allow-logon-through-rdp.png]]
	*Figure 6 — `secpol.msc` → "Allow log on through Remote Desktop Services" showing Remote Desktop Users.*
- and at the domain level (Default Domain Controllers Policy):
	![[gpo-allow-logon-through-rdp-dc.png]]
	*Figure 7 — The same right set via the Default Domain Controllers GPO.*

---

## Attack Chain

#### Service Validation

Before exploiting any services, it's usually best to validate the credential and enumerate domain users with NetExec:

- This gives an attacker a better look at how the domain is built, mapping out its infrastructure.
	![[nxc-smb-user-enum.png]]
	*Figure 8 — NetExec authenticates as `Yuji.Itadori` and enumerates 19 domain users (`--users`).*

```bash
# Validate the credential
nxc smb 192.168.100.10 -u Yuji.Itadori -p 'test123!' -d zeroDae.local

# Enumerate domain users
nxc smb 192.168.100.10 -u Yuji.Itadori -p 'test123!' -d zeroDae.local --users
```

Enumerate the available shares:

![[nxc-smb-shares-enum-dup.png]]
*Figure 9 — NetExec share enumeration (`--shares`): READ on IPC$, NETLOGON, SYSVOL.*

```bash
nxc smb 192.168.100.10 -u Yuji.Itadori -p 'test123!' -d zeroDae.local --shares
```

In this scenario the attacker could not find any key data in the SMB shares; however, that is not the only service available. Using NetExec's `rdp` module, the attacker verifies the compromised user can RDP into the DC:

![[nxc-rdp-validation.png]]
*Figure 10 — NetExec `rdp` module confirming `Yuji.Itadori` can authenticate over RDP to the DC.*

```bash
nxc rdp 192.168.100.10 -u Yuji.Itadori -p 'test123!' -d zeroDae.local
```

#### RDP Logon from Kali

Using the `xfreerdp3` client, the attacker can remotely log in to the machine as the user `Yuji.Itadori`. This is critical in a SOC / enterprise environment: an outsider now has an interactive session on the domain controller itself.

![[xfreerdp-rdp-session-dc.png]]
*Figure 11 — `xfreerdp3` session to the DC as `Yuji.Itadori` — full interactive desktop on Windows Server 2022.*

```bash
xfreerdp3 /v:192.168.100.10 /u:Yuji.Itadori /p:'test123!' /d:zeroDae.local /cert:ignore
```

#### What Does This Mean?

- This activity appears as a standard logon event, so how can a SOC analyst tell which is benign and which is malicious?
- Defenders can add specific conditions to a detection rule that key on the remote source IP of the logon. Any external IPs outside the organization can be flagged for further review.
- Excluding Privileged Access Workstations (PAWs) removes the expected admin-RDP noise so the real signal stands out.

---

## Attack Telemetry in Sentinel

The attacker's logon was captured and flagged with the detection query below. The RDP logon lands in the `SecurityEvent` table as a **4624 / LogonType 10** event, stamped with the attacker's source IP (`192.168.100.50`).

![[rdp-detection-query.png]]
*Figure 12 — The RemoteInteractive logon in Sentinel.*

```kql
// RDP successful-logon hunting query
// Successful RDP = EventID 4624 (success) + LogonType 10 (RemoteInteractive)
// MITRE ATT&CK: T1021.001 - Remote Services: Remote Desktop Protocol
let PAW_Hosts = dynamic(["PAW01","ADMIN-WKS01"]);   // known Privileged Access Workstation hostnames (allowlist)
let PAW_IPs   = dynamic(["192.168.100.20"]);        // known PAW source IPs (allowlist)
SecurityEvent
| where EventID == 4624                                  // successful logon
| where LogonType == 10                                  // RemoteInteractive = RDP
| where isnotempty(IpAddress) and IpAddress !in ("-","127.0.0.1","::1")  // genuine remote source only
| where WorkstationName !in (PAW_Hosts)                 // exclude admin workstations by name
| where IpAddress !in (PAW_IPs)                          // exclude known PAW source IPs
| project TimeGenerated, Account, Computer, IpAddress, WorkstationName, LogonProcessName
| order by TimeGenerated desc
```

---

## Scheduled Analytics Rule

Deploy the detection as a scheduled analytics rule so it raises MITRE-mapped incidents automatically.

| Setting           | Value                                                               |
| ----------------- | ------------------------------------------------------------------- |
| Name              | RDP Lateral Movement – Remote Interactive Logon (4624 / Type 10)    |
| Severity          | High                                                                |
| MITRE ATT&CK      | Lateral Movement → **T1021.001 (RDP)** · **T1078 (Valid Accounts)** |
| Rule logic        | The KQL above                                                       |
| Entity mapping    | Account → `Account` · Host → `Computer` · IP → `IpAddress`          |
| Schedule          | Run every 5 minutes · 1-hour lookback                               |
| Incident creation | Enabled (grouped alerts)                                            |

### General Info

The Name, Description, Severity, and MITRE ATT&CK mapping describe the action/function of the rule. This particular rule is modeled after RDP lateral movement via a Remote Interactive logon for a valid domain account (T1078).

![[rdp-rule-general.png]]
*Figure 13 — Analytics rule General tab: name, description, and severity.*

![[rdp-rule-mitre-mapping.png]]
*Figure 14 — MITRE ATT&CK mapping: Lateral Movement → T1021.001 (RDP) · T1078 (Valid Accounts).*

### Rule Setup Logic

#### Entity Mapping

- I linked the `Account`, `IP`, and `Host` fields so Sentinel surfaces the specific data needed to get the full picture.
- This benefits the SOC in many ways — automatically linking related alerts and tracking threats across the network.
	![[rdp-rule-logic-entity-mapping.png]]
	*Figure 15 — Entity mapping: Account, Host, and IP.*

#### Query Breakdown

From the DC's logs, this scheduled analytics rule filters for successful RDP logons from a real remote source, dropping anything coming from a trusted admin workstation (by name or IP), and surfacing untrusted/foreign IP addresses (192.168.100.50):

![[rdp-rule-query-results.png]]
*Figure 16 — Rule query results: the RemoteInteractive logon from the untrusted source IP.*

```kql
let PAW_Hosts = dynamic(["PAW01","ADMIN-WKS01"]);   // known Privileged Access Workstation hostnames (allowlist)
let PAW_IPs   = dynamic(["192.168.100.20"]);        // known PAW source IPs (allowlist)
SecurityEvent
| where EventID == 4624                                                   // successful logon
| where LogonType == 10                                                   // RemoteInteractive = RDP
| where isnotempty(IpAddress) and IpAddress !in ("-","127.0.0.1","::1")   // genuine remote source only
| where WorkstationName !in (PAW_Hosts)                                   // exclude admin workstations by name
| where IpAddress !in (PAW_IPs)                                           // exclude known PAW source IPs
| project TimeGenerated, Account, Computer, IpAddress, WorkstationName, LogonProcessName
```

- `let PAW_Hosts = dynamic([...])` — a named list of trusted admin-workstation hostnames used to filter out normal traffic.
- `let PAW_IPs = dynamic([...])` — an approved IP-address allowlist of trusted sources.
- `SecurityEvent` — start with the DC's Windows security logs.
- `where EventID == 4624` — pulls only **successful** logons (4624).
- `where LogonType == 10` — narrows to **LogonType 10 (RemoteInteractive)**, which is RDP specifically — excluding local console (type 2), network (type 3), and service logons.
- `where isnotempty(IpAddress) and IpAddress !in ("-","127.0.0.1","::1")` — drops blank IPs and loopback/local sources (`-`, `127.0.0.1`, `::1`) so only genuine remote logons remain.
- `where WorkstationName !in (PAW_Hosts)` — drops any hostname on the trusted PAW allowlist.
- `where IpAddress !in (PAW_IPs)` — the same exclusion, but by **source IP** — catches trusted admin sources even if the hostname doesn't come through.
- `project TimeGenerated, Account, Computer, IpAddress, WorkstationName, LogonProcessName` — prints only the fields that matter for triage.

#### Scheduling

- For this environment we set the rule to run automatically every **5 minutes** against the log data matched by the **rule query**.
- This is the core function of the feature: it creates an autonomous process that supports 24-hour monitoring in real-world SOC environments.
	![[rdp-rule-query-scheduling.png]]
	*Figure 17 — Query scheduling: run every 5 minutes, 1-hour lookback.*

---

## Skills Demonstrated

- **Offensive AD** — stolen-credential lateral movement against a live domain controller: SMB enumeration and an interactive RDP session with NetExec and `xfreerdp` (T1021.001 · T1078)
- **Detection engineering** — writing a context-driven KQL analytics rule (4624 / LogonType 10) with PAW allowlisting and entity mapping
- **Detection tuning** — reducing false positives by excluding Privileged Access Workstations by hostname and source IP
- **Full attack lifecycle** — credential foothold → enumeration → RDP session → SIEM detection → incident
- **MITRE ATT&CK mapping** — classifying the detection as T1021.001 (RDP) and T1078 (Valid Accounts)

---
