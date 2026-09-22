# SOC-Detection-Lab
Attacker-informed detection engineering hybrid on-prem AD → Microsoft Sentinel, with attack simulations mapped to MITRE ATT&amp;CK and custom KQL detection rules

Attacker-informed detection engineering. A hands-on lab that streams telemetry from an on-premises Active Directory environment into Microsoft Sentinel, simulates real credential attacks, and detects them with custom KQL analytics rules — every detection mapped to MITRE ATT&CK.

The theme of this lab is that each detection is credible because the attack behind it is understood. Projects run the offensive technique first, then build the detection that catches it, then (where relevant) prove impact.

## Architecture  

```plain text
┌─────────────────┐         ┌──────────────────────────────┐
│  Kali (attacker)│         │  Windows Server 2022 DC      │
│  192.168.100.50 │──SMB──▶|  zeroDae.local(192.168.100.10)│
│ Impacket/NetExec│  LDAP   |  Security Event Log          │
└─────────────────┘         └──────────────┬───────────────┘
                                           │ Azure Arc + Azure Monitor Agent
                                           │ Data Collection Rule
                                           ▼
                           ┌──────────────────────────────┐
                           │  Log Analytics (law-zerodae)  │
                           │  Microsoft Sentinel           │
                           │  KQL analytics rules → Incidents│
                           └──────────────────────────────┘
```
A single hybrid pipeline underlies every project: the domain controller stays on-premises and is projected into a cloud SIEM via Azure Arc — the pattern most enterprises actually use to monitor legacy infrastructure, rather than running everything natively in the cloud.

## Projects 


| Project | Technique | MITRE ATT&CK |  Status    |
| ------- | --------- | ------------ | ---------- |
| On-Prem AD → Sentinel Pipeline  | Hybrid log ingestion (Arc + AMA + DCR)  |  |  ✅ |
| Brute-Force / Password-Spray Detection | Password spraying | T1110.003 | ✅ |
| Kerberoasting: Attack, Detection & Cracking | Kerberoasting | T1558.003 | ✅ |


Each project folder contains its own writeup, KQL, and screenshots.

## Stack
* Cloud SIEM: Microsoft Sentinel · Log Analytics · KQL
* Log pipeline: Azure Arc · Azure Monitor Agent · Data Collection Rules
* Detection targets: Windows Server 2022 Active Directory (zeroDae.local)
* Attacker tooling: Kali Linux · Impacket · NetExec · hashcat
* Framework: MITRE ATT&CK

## What This Lab Demonstrates
* Hybrid cloud detection — projecting on-prem AD into a cloud SIEM (not a cloud-native shortcut)
* Detection engineering — writing, parsing, and tuning KQL analytics rules with entity mapping
* Attack simulation — running real credential attacks against a live domain controller
* MITRE ATT&CK coverage — every detection classified to a technique
* The full loop — attack → telemetry → detection → incident → (impact)

## Related Writeups

Longer, narrative versions of these builds are published as a series on Medium:

* [Setting Up Windows Server 2022 with Active Directory (foundation)](https://medium.com/@daemonwork2001)
* [Deploying a Wazuh SIEM with Sysmon and Windows Event Monitoring (on-prem SIEM track)](https://medium.com/@daemonwork2001)
* [Microsoft Sentinel - Azure Honeypot Detection Lab](https://zerodaex.github.io/daemondoesIT.github.io/)






