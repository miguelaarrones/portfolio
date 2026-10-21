# Indicators of Compromise (IOCs)

| Indicator Type          | Defanged Value                                                     | Context / Threat Association               |
| :---------------------- | :----------------------------------------------------------------- | :----------------------------------------- |
| **Originating IP**      | `198[.]51[.]100[.]45`                                              | Rogue SMTP relay (Failed SPF/DKIM)         |
| **Attacker Domain**     | `secure-billing-portal[.]cc`                                       | Phishing `Reply-To` & credential harvester |
| **Lure URL**            | `hxxp://login[.]secure-billing-portal[.]cc/dispute?id=89218`       | Embedded link inside email body            |
| **C2 Staging Domain**   | `c2-traffic[.]xyz`                                                 | Host serving stage-2 binary payload        |
| **Payload URL**         | `hxxp://c2-traffic[.]xyz/stage2[.]exe`                             | Second-stage download cradle URL           |
| **File Path**           | `C:\Tools\malware[.]exe`                                           | Targeted local disk drop path              |
| **File Hash (SHA-256)** | `e69300fcac94898e315b384dd7291935b5a10813af746bbb0fe5308490983f7e` | Staged binary fingerprint                  |

---
# SOC Containment & Remediation Playbook

1. **Email Gateway (Perimeter):**
	* Implement an immediate domain block for `secure-billing-portal[.]cc` and IP block for `198[.]51[.]100[.]45`.
	* Search and purge all incoming messages from user inboxes matching sender pattern `*@attacker-infra.xyz` or subject `URGENT: Unauthorized Invoice*`.
2. **DNS & Web Proxy Blocklist:**
	* Sinkhole external domains `secure-billing-portal[.]cc` and `c2-traffic[.]xyz` on enterprise firewalls/proxies.
3. **Endpoint Containment (EDR):**
	* Add the SHA-256 hash to the EDR platform's global blocklist (preventing execution across all endpoints).
	* Delete staged artifact `C:\Tools\malware.exe` from impacted host.