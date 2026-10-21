# Lab 01 - Building a SOC Log Pipeline & Hunting Endpoint Threats (Splunk + Sysmon)
## Why I Built This Lab
Coming from a software development background, I understand how code executes and how APIs respond, but I wanted to see what happens on the system level when an adversary interacts with a machine. 

Instead of relying on browser-based cybersecurity simulators, I built an authentic on-premises log pipeline with two virtual machines. 

My goals were simple:
1. Understand how endpoint telemetry moves from an agent to a centralized SIEM.
2. Simulate realistic attacker techniques (authentication brute force, registry persistence, Living-Off-The-Land binaries).
3. Author practical SPL (Splunk Processing Language) detection queries and handle the data quirks of Windows event logging.

You can view the lab architecture [here](lab_architecture_network_setup.md)

---
## Scenarios
### [Scenario 1 - Authentication Guessing & Brute-Force (T1110.001)](scenarios/scenario_1_brute_force.md)
### [Scenario 2 - Persistence via Registry Run Key (T1547.001)](scenarios/scenario_2_persistence.md)
### [Scenario 3 - LOLBAS Download Attempt & Antivirus Interaction (T1197)](scenarios/scenario_3_lolbas.md)

--- 
## Practical Troubleshooting & Engineering Hurdles

Building this pipeline was not plug-and-play. 

I ran into three practical engineering problems that required root-cause analysis:
### 1. Ubuntu LVM Partition Allocation
* **The Problem:** 
	* The VM was given a 30 GB virtual disk, but `df -h /` showed only 14 GB allocated. 
	* Splunk soon halted search operations with a safety error: `The minimum free disk space (5000MB) reached`.
* **Root Cause:** 
	* Ubuntu Server's installer defaults to allocating only 50% of the volume group size to allow room for snapshots.
* **Fix:**
	* I used LVM's live expansion tool to extend the partition to 100% of the free pool and grow the filesystem online:
		```bash
			sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv -r
		```
	- This expanded root capacity to ~29 GB instantly without unmounting or rebooting.

### 2. Sysmon Subscription Failure (`errorCode=5`)
* **The Problem:** 
	* Windows Security logs forwarded to Splunk, but Sysmon operational logs did not appear.
	* Splunk’s internal forwarder log (`splunkd.log`) showed:
  `WinEventLogChannel::init: Init failed, unable to subscribe to Windows Event Log channel 'Microsoft-Windows-Sysmon/Operational': errorCode=5`.
* **Root Cause:** 
	* Error code 5 on Windows indicates `Access Denied`. 
	* The forwarder service was running under the virtual identity `NT SERVICE\SplunkForwarder`, which lacked Access Control List (ACL) read rights to the Sysmon event channel.
* **Fix:** 
	* In `services.msc`, I switched the `SplunkForwarder` service account to run under `Local System`. 
	* This granted it inherited administrative rights to read all local event channels.

### 3. Data Normalization & Duplicate Field Names
* **The Problem:** 
	* When forwarding plain-text Windows logs, Splunk's key-value extractor grouped both the caller machine (`-` or `SYSTEM`) and the target user (`test_adversary`) into a single multi-value list named `Account_Name`. 
	* Searches like `stats count by Account_Name` doubled the counts and broke basic threshold filtering.
* **Fix:** 
	* I set `renderXml = 1` inside `inputs.conf` and installed the official **Splunk Add-on for Microsoft Windows (`Splunk_TA_windows`)** on Ubuntu. 
	* The Add-on parses XML tags natively and cleanly separates the caller (`SubjectUserName`) from the target (`TargetUserName`), allowing standard, readable SPL queries.

--- 

## Key Lessons Learned
1. **Endpoint context is critical:** 
	- Windows Security events provide high-level accounting (`4625`, `4624`), but Sysmon provides the operational evidence (parent PID, full command-line arguments, registry payload details).
2. **Data ingestion requires normalization:** 
	- Without understanding how a SIEM parses XML versus raw text, detection queries will either fail or require unnecessarily complex regex workarounds.
3. **Thresholds prevent alert fatigue:** 
	- Good detection engineering balances catching malicious activity with filtering out normal user errors.