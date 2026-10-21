# Scenario 2: Defense Evasion via Event Log Clearing (MITRE ATT&CK T1070)

Once an attacker gains a foothold, a common defense evasion technique is wiping local event logs to hinder incident responders and remove forensic traces.

## Attack Command Executed:

  ```powershell
  wevtutil.exe cl Application
  ```
## Detection and Response Rule (D&R)

* **Detection Rule (`detect-wevtutil-log-clear`):**
```yaml
event: NEW_PROCESS
op: and
rules:
  - op: ends with
    path: event/FILE_PATH
    value: wevtutil.exe
    case sensitive: false
  - op: contains
    path: event/COMMAND_LINE
    value: cl
    case sensitive: false
```

* **Response Action:**
```yaml
- action: report
  name: Defense Evasion - Windows Event Log Cleared (T1070)
  publish: true
  priority: 1
```
## Observed Forensic Artifact:

* **Target Event:** `NEW_PROCESS`
* **Process Path:** `C:\WINDOWS\system32\wevtutil.exe` (PID: `6980`)
* **Arguments:** `"C:\WINDOWS\system32\wevtutil.exe" cl Application`
* **Parent Executable (`event/PARENT`):** `powershell.exe` (PID: `8808`)
* **SOC Significance:** Classified as **Priority 1 (Critical)** because standard operational workflows should never wipe security or application event logs outside of automated archival maintenance.
![[wevutil_cleanup.png]]