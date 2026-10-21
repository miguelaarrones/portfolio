# Lab 03: Phishing Triage, Script Deobfuscation & Incident Scoping (CyberChef & Splunk)

## Why I Built This Lab

In a Security Operations Center (SOC), user-reported suspicious emails make up a significant portion of the daily alert queue. 

While automated email security gateways (like Proofpoint or Defender for Office 365) block high-confidence spam, adversaries continually craft evasive initial-access lures designed to bypass perimeter filters.

In **Lab 01** and **Lab 02**, I focused on post-exploitation endpoint telemetry (SIEM logging and live EDR tracking).

In this lab, I stepped into the role of a Tier 1 SOC Analyst handling the very start of the attack lifecycle: **Initial Access Triage**.

My goals were to:
1. Verify authentication headers (`Received:`, SPF, DKIM, DMARC) in a raw `.eml` file to definitively prove display-name spoofing.
2. Safely unpack a multi-stage obfuscated loader script using **CyberChef** to extract external staging URLs and file drop targets.
3. Perform realistic Tier 1 artifact triage: calculating cryptographic hashes, simulating OSINT/Threat Intel lookups, and understanding where the junior analyst scope ends and specialized reverse engineering begins.
4. Pivot back to my SIEM (**Splunk**) to execute an enterprise-wide threat hunt, proving whether the extracted Indicators of Compromise (IOCs) touched disk on the monitored fleet.

You can view the architecture and the investigation pipeline of this lab [here](lab_architecture_investigation_pipeline.md)

---
## Investigation Walkthrough
### [Phase 1: Authentication Header Triage](investigation/phase_1_email_triage.md)
### [Phase 2: Multi-Stage Script Deobfuscation](investigation/phase_2_script_deobfuscation.md)
### [Phase 3: Artifact Triage & Threat Hunt Pivot](investigation/phase_3_artifact_triage_threat_hunt.md)
### [Indicators of Compromise (IOCs), Containment & Remediation](investigation/phase_4_iocs_containment.md)

---
## Technical Hurdles & Troubleshooting

### The UTF-16LE Character Misalignment (Mojibake / Chinese Glyph Trap)
* **The Problem:** 
	* During the initial deobfuscation of the reversed Base64 payload in CyberChef, the recipe output rendered completely unreadable Chinese characters (`敳敲數牥獟普...`) instead of cleartext PowerShell code.
* **Root Cause:** 
	* PowerShell’s `-EncodedCommand` (`-enc`) parameter requires text to be formatted in **UTF-16LE (Little-Endian Unicode)**, where every character is represented by two bytes (the ASCII byte followed by a null byte `0x00`). 
	* When a string is reversed at the raw character level prior to Base64 decoding, the 2-byte boundaries become misaligned:
		* Two distinct single-byte characters (e.g., `'s'` and `'e'` / `0x73 0x65`) were grouped into a single 16-bit integer (`0x6573`).
		* In the Unicode table, `0x6573` maps directly to the CJK ideograph **`敳`**.
* **The Fix:** 
	* I learned that character reversal operations must align with the underlying byte structure.
	* By structuring the script generation to account for PowerShell's Unicode array buffer before reversing, CyberChef's pipeline cleanly inverted the string buffer first, decoded the standard Base64 transport layer second, and finally decoded `UTF-16LE (1200)` without shifting byte boundaries.

--- 
## Key Lessons Learned

1. **Email Headers Are Indisputable:** 
	- Attackers can easily forge display names in the `From:` line, but they cannot forge cryptographic signatures (`DKIM`) or manipulate upstream MTA IP addresses (`Received:` headers).
2. **Real-World Deobfuscation Requires Encoding Awareness:** 
	- Decoding PowerShell payloads requires understanding UTF-16LE Unicode character representation. 
	- Failing to account for 2-byte character boundaries results in Mojibake/text corruption.