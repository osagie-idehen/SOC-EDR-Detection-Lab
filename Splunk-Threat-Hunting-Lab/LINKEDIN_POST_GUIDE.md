# LinkedIn Showcase Guide: Project 3 (SIEM Threat Hunting & Splunk SOC Alerting)

This guide provides the exact text, formatting, and image assets to feature **Project 3** on your LinkedIn profile and publish a high-engagement post to attract cybersecurity recruiters and hiring managers.

---

## Part 1: High-Impact LinkedIn Post (Copy & Paste)

*Attach the generated visual dashboard image from your folder:*  
📁 `C:\Users\HP\Downloads\SOC-Lab-Portfolio\Splunk-Threat-Hunting-Lab\splunk_soc_dashboard.png`

```text
🔍 What does an active domain controller compromise look like in a SIEM?

As part of my hands-on detection engineering & SOC portfolio, I built and investigated an enterprise threat hunting lab in Splunk Enterprise analyzing a multi-stage intrusion targeting a primary Domain Controller (DC-CORP-01).

Here is a breakdown of the investigation (INC-20261025-003):

🎯 The Threat Scenario:
An external threat actor operating from 185[.]220[.]101[.]5 executed an automated brute-force attack, breached a high-privilege account, spawned an obfuscated reverse shell, established persistence via rogue Domain Admin creation, staged secondary payloads, and wiped the Windows Security Event Log.

🛠️ Detection Engineering & Splunk SPL Correlations:
1. Brute-Force & Password Spraying (MITRE T1110.001):
• Ingested Windows Security Event 4625.
• Correlated high-frequency failures: 8 failed attempts in < 60 seconds targeting Administrator, jdoe, and sql_svc.
• Authored SPL threshold rule triggering when failures exceed 5 attempts per source IP.

2. Breached Credential Correlation (MITRE T1078):
• Correlated Event 4624 (Logon Type 3 - Network) occurring immediately after Event 4625 spikes from the same IP.
• Confirmed unauthorized remote access using the built-in Administrator credential.

3. Obfuscated PowerShell Reverse Shell & LOLBAS Ingress (MITRE T1059.001 / T1105):
• Sysmon Event ID 1 caught powershell.exe -nop -w hidden -enc JABj... establishing outbound C2 over port 443.
• Detected certutil.exe abusing -urlcache to stage update_agent.exe in C:\Windows\Temp\.

4. Rogue Domain Admin Persistence (MITRE T1098):
• Event 4720 flagged backdoor user creation (svc-backup-admin).
• Event 4728 alerted on immediate privilege escalation into the Domain Admins global security group.

5. Anti-Forensics & Defense Evasion (MITRE T1070.001):
• Event 1102 alerted on unauthorized clearing of the Windows Security Audit Log.

🛡️ Containment & Incident Handling (NIST SP 800-61 Rev. 2):
• Built an automated PowerShell threat hunting engine (hunt_threats.ps1) to parse and score telemetry.
• Isolated DC-CORP-01 via EDR and terminated running adversary process trees.
• Disabled and purged rogue user svc-backup-admin.
• Executed a dual KRBTGT password reset across Active Directory to invalidate all active Kerberos TGT tickets (Golden Ticket mitigation).
• Dropped adversary IP at perimeter firewalls.

Full SPL queries, Splunk dashboard XML, and investigation reports are available on my GitHub:
🔗 https://github.com/osagie-idehen/SOC-EDR-Detection-Lab/tree/main/Splunk-Threat-Hunting-Lab

#Cybersecurity #SOCAnalyst #ThreatHunting #Splunk #BlueTeam #IncidentResponse #DetectionEngineering #MITREATTACK #CompTIA #SecurityPlus #ActiveDirectory #InfoSec
```

---

## Part 2: LinkedIn Profile "Featured" / "Projects" Section

Add this directly to your LinkedIn profile under **Add profile section ➔ Recommended ➔ Add projects**:

* **Project Name:**  
  `SIEM Threat Hunting, Detection Engineering & SOC Alerting Lab (Splunk Enterprise)`

* **Associated with:**  
  `Security Operations Center (SOC) Analyst` *(or leave blank)*

* **Start Date:**  
  `October 2026` &bull; Check **"Currently working on this"**

* **Project URL:**  
  `https://github.com/osagie-idehen/SOC-EDR-Detection-Lab/tree/main/Splunk-Threat-Hunting-Lab`

* **Skills (Add tags):**  
  `Splunk`, `SIEM`, `Threat Hunting`, `Incident Response`, `Detection Engineering`, `PowerShell`, `Windows Event Logs`, `Sysmon`, `MITRE ATT&CK`, `Active Directory Security`

* **Description:**  
```text
• Investigated an active multi-stage intrusion on an enterprise Domain Controller simulating brute-force access, encoded PowerShell C2, and rogue admin creation (MITRE ATT&CK T1110, T1059, T1098).
• Authored production Splunk Search Processing Language (SPL) correlation rules (savedsearches.conf) to detect threshold anomalies and privilege escalation.
• Engineered an interactive dark-mode Splunk SOC XML dashboard and built an automated PowerShell log analysis engine (hunt_threats.ps1).
• Authored a formal SOC incident investigation report detailing host isolation, account eradication, and dual KRBTGT Kerberos Golden Ticket mitigation.
```
