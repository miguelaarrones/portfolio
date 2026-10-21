# Scenario 1: Execution Policy Bypass (MITRE ATT&CK T1059.001)

Adversaries frequently launch scripts by bypassing local execution restrictions using command-line arguments to evade default PowerShell policies.

## **Attack Command Executed:**

  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'SOC Lab Test: Scenario 1 ExecutionPolicy Bypass'"
  ```
## Detection and Response Rule (D&R)

* **Detection** (`detect-powershell-bypass`):**
```yaml
event: NEW_PROCESS
op: and
rules:
  - op: ends with
    path: event/FILE_PATH
    value: powershell.exe
    case sensitive: false 
  - op: contains
    path: event/COMMAND_LINE
    value: -ExecutionPolicy Bypass
    case sensitive: false
```

* **Response:**
```yaml
- action: report
  name: Suspicious PowerShell ExecutionPolicy Bypass (T1059.001)
  publish: true
  priority: 3
```
## Observed Forensic Artifact:

* **Child Executable (`event/FILE_PATH`):** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (PID: `8272`)
* **Command Line (`event/COMMAND_LINE`):** `"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass ...`
* **Parent Executable (`event/PARENT`):** `powershell.exe` (PID: `8808`)
* **Signature Status (`FILE_IS_SIGNED`):** `1` (Highlighting why signature-based AV ignores it: the executing binary itself is an authentic Microsoft-signed binary).
![[powershell_bypass.png]]