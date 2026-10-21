# Cybersecurity Portfolio: Blue Team Operations, Detection & Security Research

Hi, I'm a software developer transitioning into cybersecurity. My primary operational target is a **Security Operations Center (SOC) Analyst (Tier 1 / Junior)** role, with a strong focus on defensive engineering, malware analysis, and offensive concepts.

Coming from a development background, I understand programming logic, data structures, low-level OS behavior, and how software interacts with system memory. Rather than relying on purely theoretical certifications, this repository serves as a centralized hub documenting practical, reproducible technical labs across:

1. **SOC Operations & Detection Engineering:** SIEM telemetry pipelines, EDR rule creation, threat hunting, and network defense.
2. **Malware Analysis & Vulnerability Research:** Static and dynamic artifact dissection, PE inspection, and exploit mechanics.
3. **Adversary Emulation & Red Teaming:** Emulating real-world threat actor tradecraft to validate and stress-test defensive controls.

---
## 1. SOC Defense & Detection Roadmap (Core Labs)

| Lab | Focus Area | Core Tech Stack | Status |
| :--- | :--- | :--- | :--- |
| **Lab 1** | **SIEM Pipeline & Host Log Analysis** | Splunk Enterprise, Sysmon, Windows 10/11, Ubuntu Server | **Completed** |
| **Lab 2** | **EDR Operations & Threat Emulation** | LimaCharlie EDR, Atomic Red Team, PowerShell | **In Progress** |
| **Lab 3** | **Phishing & Malicious Artifact Triage** | REMnux, CyberChef, Sandbox Analysis | *Queued* |
| **Lab 4** | **Perimeter Defense & Firewall Monitoring** | pfSense, Suricata IDS/IPS, Syslog to SIEM | *Queued* |
### Lab Summaries

#### Lab 1: Centralized SIEM & Telemetry Pipeline (Splunk + Sysmon)
* **Objective:** Build a self-contained log forwarding pipeline from scratch and detect authentication abuse and Living-Off-The-Land (LOLBAS) tradecraft.
* **Architecture:** Splunk Enterprise hosted on Ubuntu Server 24.04 LTS ingesting events from a Windows client running Microsoft Sysmon via Splunk Universal Forwarder.
* **What I Simulated:**
	* **Brute-Force & Account Discovery (EventCode 4625/4624):** Simulated SMB password guessing using a PowerShell loop. Wrote threshold-based SPL queries to distinguish benign typos from sustained attacks.
	* **Registry Run Key Persistence (Sysmon EventCode 13):** Emulated auto-start persistence via `reg.exe` targeting `CurrentVersion\Run`.
	* **LOLBAS File Transfer (Sysmon EventCode 1):** Tested file ingress using native tools (`certutil` vs. `bitsadmin`), observed real-time Microsoft Defender blocking behavior, and tracked parent-child process lineage (`powershell.exe` $\rightarrow$ `bitsadmin.exe`).

#### Lab 2: Enterprise EDR & Attack Emulation (LimaCharlie + Atomic Red Team)
* **Objective:** Move from passive log analysis to active, kernel-level endpoint detection, real-time process monitoring, and host containment.
* **Architecture:** LimaCharlie cloud EDR tenant paired with an active sensor deployed on a Windows endpoint, running the Atomic Red Team execution framework.
* **Focus Areas:**
	* Analyzing process trees, memory handles, and loaded DLLs in real time.
	* Emulating mapped MITRE ATT&CK techniques (LSASS credential dumping, execution policy bypasses).
	* Writing custom Detection & Response (D&R) rules and executing automated host isolation.

#### Lab 3: Phishing & Malicious Artifact Triage (REMnux + CyberChef)  *(In Progress)*
* **Objective:** Triage suspicious emails and deobfuscate initial-access scripts typically reported by end users.
* **Focus Areas:**
	* Extracting and verifying email authentication headers (`Received:`, SPF, DKIM, DMARC) to identify spoofing.
	* Safely unpacking and decoding layered scripts (base64, character replacements, download cradles) in CyberChef.
	* Defanging and documenting Indicators of Compromise (IOCs) for blocklists and incident reports.

#### Lab 4: Firewall & Perimeter Monitoring (pfSense + Syslog to SIEM) *(Queued)*
* **Objective:** Understand network boundaries, stateful packet filtering, and perimeter alert correlation.
* **Architecture:** pfSense Community Edition virtual router routing traffic for an internal test segment and shipping firewall state logs via Syslog (UDP 514) to the SIEM.
* **Focus Areas:**
	* Differentiating stateful connection drops (`[S]`, `[R]`, `[F]` flags) during external port scans.
	* Setting up strict egress filtering to detect unauthorized outbound connections and beaconing intervals.
	* Correlating external firewall blocks with internal endpoint telemetry.

---
## 2. Advanced Security Research & Offensive Operations *(Upcoming Sections)*

To bridge the gap between application development and defensive analysis, this repository will also host standalone technical write-ups in deeper research tracks:

### 🔬 Malware Analysis & Reverse Engineering
* **PE Header & Executable Inspection:** Static dissection of Portable Executable (PE) headers, section characteristics (`.text`, `.rdata`), and import/export address tables (IAT/EAT).
* **Behavioral Sandboxing:** Analyzing runtime indicators, dropped files, and C2 callbacks in isolated sandbox environments.
* **Script Deobfuscation:** Unpacking weaponized VBA macros, heavily obfuscated PowerShell, and batch staging scripts.

### 🎯 Vulnerability Research & Red Teaming
* **Vulnerability Analysis:** Replicating known CVEs in local environments to analyze root-cause mechanics (buffer overflows, injection flaws, privilege escalation).
* **Adversary Tradecraft Simulation:** Hands-on red team exercises demonstrating how attackers bypass endpoint controls, harvest credentials, and maintain C2 channels—used directly to inform better detection rules.

---
## Contact & Profile
* **LinkedIn:** [https://es.linkedin.com/in/maarrones](https://es.linkedin.com/in/maarrones)
* **Email:** [miguelaarrones@icloud.com](mailto:miguelaarrones@icloud.com)
* **Location:** Balearic Islands, Spain