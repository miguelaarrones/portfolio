# Scenario 2 - Persistence via Registry Run Key (T1547.001)

I simulated an adversary ensuring their payload survives a reboot by adding an entry to the current user's autostart hive:
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdater" /t REG_SZ /d "C:\Windows\System32\cmd.exe /c calc.exe" /f
```
### The Detection Query (Sysmon EventCode 13 - RegistryValueSet):

```spl
index="endpoint" EventCode=13 TargetObject="*CurrentVersion\\Run*"
| table _time, Computer, User, Image, TargetObject, Details
```
* **Investigation takeaway:** The results clearly showed `reg.exe` writing `cmd.exe /c calc.exe` under key `SecurityUpdater`. In the same search window, I also spotted legitimate software (`msedge.exe` writing `MicrosoftEdgeAutoLaunch`), giving me a realistic look at how analysts differentiate benign baseline activity from suspicious persistence.
### Dashboard
![[registry_run_modification.png]]