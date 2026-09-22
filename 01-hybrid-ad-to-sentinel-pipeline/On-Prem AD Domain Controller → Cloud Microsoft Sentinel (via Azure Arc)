## Objective 

Ingest Windows Security telemetry from an on-premise Active Directory domain controller into a cloud SIEM (Microsoft Sentinel), establishing the detection foundation for later projects (brute-force detection, kerberoasting).

I connected my existing on-prem DC to Sentinel allowing me to demonstrate a hybrid on-prem -> cloud pipeline. This displays a more distinctive skill than an all-in0Azure deploy.

## Environment

- DC: Windows Server 2022, `WIN-PLG4VMVBU6A`, domain `zeroDae.local` , running in VirtualBox (on-prem).
- Network: Adapter 1 - Internal Network 9domain segment, static `192.168.100.10`); Adapter 2=NAT (internet egress).
- Cloud: Azure subscription -> Resource Group `rg-sentinel-lab` -> Log Analytics workspace `law-zerodae` -> Microsoft Sentinel enabled (31-day / 10 GB-per-day free trial)

## Steps completed 

1. Networking for Arc 
	- Added a second NIC (NAT) so the DC has internet egress, keeping the internal NIC for the domain. Cleared the dead default gateway on the internal NIC so the internet route comes only from NAT.
	- Added DNS forwarders (`8.8.8.8`, `1.1.1.1`) on the DC — required because the DC is its own DNS server and couldn't otherwise resolve external Azure endpoints.
	- Verified with `ping 8.8.8.8` (route) and `nslookup google.com` (resolution).
2. Azure setup: Created Resource Group + Log Analytics workspace, enabled Sentinel )started trial, set cost guardrails (budget alert + workspace daily cap). Sentinel now managed via the Defender portal (`security.microsoft.com`).
3. Azure Arc onboarding: Generated the onboarding script in the portal, ran `OnboardingScript.ps1` in elevated PowerShell on the DC, authenticated via device login. Installed the Azure Connected Machine agent (`azcmagent`). DC confirmed **Connected** under Azure Arc -> Machines.
4. Log collection: Installed the **Windows Security Events** content-hub solution, opened the **Windows Security Events via AMA** connector, created a Data Collection Rule scoped to the Arc DC (auto-installed the Azure Monitor Agent), set to collect **All Security Events**. (AMA on a non-Azure machine requires Arc)
5. Audit policy: Edited the Default Domain Controllers Policy -> Advanced Audit Policy Configuration -> enabled **Audit Logon** (4624/4625), **Kerberos Service Ticket Operations** (4769), **Kerberos Authentication Service** (4768/4771), all Success + Failure. Ran `gpupdate /force`. Required because the DCR only collects events that auditing actually writes.
6. Verification: `SecurityEvent | take 10` in workspace Logs returned live events from `WIN-PLG4VMVBU6A.zeroDae.local` — pipeline confirmed end to end.

![Sentinel Logs](https://raw.githubusercontent.com/zeroDaex/SOC-Detection-Lab/main/01-hybrid-ad-to-sentinel-pipeline/Images/Sentinel-Logs.png)
