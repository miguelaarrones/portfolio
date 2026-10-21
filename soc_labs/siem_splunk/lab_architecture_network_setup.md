# Lab Architecture & Network Setup

![[soc_labs/siem_splunk/assets/lab_architecture.png]]

* **SIEM Node:** Ubuntu Server 24.04 (Headless, 2 vCPUs, 4 GB RAM, 30 GB disk).
* **Target Node:** Windows 11 Enterprise Evaluation (2 vCPUs, 4 GB RAM, 40 GB disk).
* **Virtual Network:** VMware NAT adapter (`VMnet8`), isolating the lab traffic from my home network while preserving internet access for updates.