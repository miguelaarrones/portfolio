# Scenario 1 - Authentication Guessing & Brute-Force (T1110.001)

To simulate an adversary attempting rapid credential guessing against a target account, I ran a PowerShell loop firing 10 failed logon attempts via SMB:
```powershell
1..10 | ForEach-Object {
    net use \\127.0.0.1\IPC$ /user:test_adversary "WrongPass$_" 2>$null
}
```
### The Detection Query:

```spl
index="endpoint" (EventCode=4625 OR EventCode=4624)
| stats 
    count(eval(EventCode=4625)) as Failed_Logons,
    count(eval(EventCode=4624)) as Successful_Logons,
    values(WorkstationName) as Calling_Machine,
    values(IpAddress) as Source_IP
    by TargetUserName
| where Failed_Logons >= 5
```
* **Why this logic:** Normal users mistype passwords once or twice. Adding `where Failed_Logons >= 5` filters out daily noise and focuses on rapid guessing. Counting both 4625 (failure) and 4624 (success) lets me answer the most important triage question: *did the attacker actually break in?*
### Tracing the Process Lineage (Sysmon EventCode 1)

A Security log alert tells an analyst *who* failed to log in, but it doesn't show *what program* initiated the connection. I used Sysmon to trace the process tree:

```spl
index="endpoint" EventCode=1 Image="*net.exe"
| table _time, Computer, User, ParentImage, Image, CommandLine
```
* **What this revealed:** Sysmon clearly captured `powershell.exe` launching `net.exe` and exposed the exact loop arguments (`/user:test_adversary WrongPass...`), proving the activity was an automated script rather than human console input.
### Dashboard
![[brute_force_process_lineage.png]]