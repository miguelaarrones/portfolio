# Phase 3: Artifact Triage & Threat Hunt Pivot

## 1. Cryptographic Fingerprinting (PowerShell)

On the analysis VM, I generated the cryptographic hashes for the staged binary:

```powershell
Get-FileHash -Path "C:\Tools\malware.exe" -Algorithm SHA256
Get-FileHash -Path "C:\Tools\malware.exe" -Algorithm MD5
```

* **SHA-256 Hash:** `E69300FCAC94898E315B384DD7291935B5A10813AF746BBB0FE5308490983F7E`
* **Operational Value:** While file names are easily changed by threat actors, cryptographic hashes provide an immutable identifier to query threat intelligence repositories (VirusTotal / AlienVault OTX) and configure EDR blocklists.
* **Notes**: An ImpHash would be a stronger option to identify threats.
## 2. Enterprise Threat Hunt Pivot (Splunk)
To answer the critical escalation question - *"Has anyone else in the company downloaded or executed this file?"* - I queried our centralized Splunk SIEM:

```spl
index="endpoint" EventCode=1 (CommandLine="*c2-traffic.xyz*" OR CommandLine="*malware.exe*" OR Image="*malware.exe*")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

* **Result:** Telemetry verified that execution was restricted to the isolated test endpoint (`DESKTOP-LQRC88Q`). No lateral spread or secondary executions were detected fleet-wide.