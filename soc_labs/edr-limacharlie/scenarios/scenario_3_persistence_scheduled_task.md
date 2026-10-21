# Scenario 3: Persistence via Scheduled Task Creation (MITRE ATT&CK T1053.005)

Threat actors establish persistence by configuring Windows Scheduled Tasks to automatically re-launch their backdoors or beacons upon system startup.
## Attack Command Executed:

  ```powershell
  SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10
  ```
## Detection and Response Rule (D&R)

* **Detection Rule (`detect-schtasks-create`):**
```yaml
event: NEW_PROCESS
op: and
rules:
  - op: ends with
    path: event/FILE_PATH
    value: schtasks.exe
    case sensitive: false
  - op: contains
    path: event/COMMAND_LINE
    value: /Create
```

* **Response Action:**
```yaml
- action: report
  name: Persistence - Scheduled Task Created (T1053.005)
  publish: true
  priority: 2
```
## Observed Forensic Artifact:

* **Target Event:** `NEW_PROCESS`
* **Process Path:** `C:\WINDOWS\system32\schtasks.exe` (PID: `6980`)
* **Arguments:** `"SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`
* **Parent Executable (`event/PARENT`):** cmd.exe` (PID: `3304`)
![[scheduled_task.png]]