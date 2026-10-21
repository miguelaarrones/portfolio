# Scenario 4: Discovery Burst & Process Ancestry Hunting (MITRE ATT&CK T1082)

Adversaries execute reconnaissance commands in rapid succession immediately after arriving on a host to determine domain membership, administrative rights, and host specifications.

## **Attack Command Executed Via AtomicLab:**
  ```powershell
  Invoke-AtomicTest T1082 -TestNumbers 1
  ```

* **Commands Executed by the Harness:**
  * `systeminfo.exe` (OS version, patches, architecture)
  * `whoami.exe` (Current user privileges)
  * `hostname.exe` (Machine name identification)
## Threat Hunting & Ancestry Analysis:

  Instead of writing an alert for single commands (which would cause false positives when IT admins run `whoami`), I inspected the sensor **Timeline** to hunt for **behavioral patterns**:
  1. **Burst Density:** Three separate discovery utilities were spawned within a narrow 1-second window.![[discovery_burst.png]]
  2. **Correlated Lineage:** Navigating through each event revealed that `systeminfo.exe`, `whoami.exe`, and `hostname.exe` all reported the exact same `PARENT_PROCESS_ID` (the interactive PowerShell console `PID 8808`).
  3. **Analyst Takeaway:** While any single command might be benign, an automated script rapidly polling three system attributes in 1 second from an interactive shell indicates adversary discovery activity.