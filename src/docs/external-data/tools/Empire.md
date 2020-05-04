
# Empire

## Description

### MITRE Description

> [Empire](https://attack.mitre.org/software/S0363) is an open source, cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python, the post-exploitation agents are written in pure [PowerShell](https://attack.mitre.org/techniques/T1086) for Windows and Python for Linux/macOS. [Empire](https://attack.mitre.org/software/S0363) was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries.(Citation: NCSC Joint Report Public Tools)(Citation: Github PowerShell Empire)(Citation: GitHub ATTACK Empire)



## Aliases

```
intentionally left blank
```

## Additional Attributes

* Type: tool
* Wiki: https://attack.mitre.org/software/S0363

# C2 Matrix Dataset

```json
{"Empire": {"Name": "Empire", "License": "BSD3", "Price": "NA", "GitHub": "https://github.com/BC-SECURITY/Empire", "Site": "", "Twitter": "@BCSecurity1", "Evaluator": "@jorgeorchilles", "Date": "1/30/2020", "Version": "3.0.5", "Implementation": "install.sh", "How-To": "Yes", "Slingshot": "Yes", "Kali": "Yes", "Server": "Python", "Agent": "PowerShell", "Multi-User": "Yes", "UI": "Web", "API": "Yes", "Windows": "Yes", "Linux": "Yes", "macOS": "Yes", "TCP": "No", "HTTP": "Yes", "HTTP2": "No", "HTTP3": "No", "DNS": "No", "DoH": "No", "ICMP": "No", "FTP": "No", "IMAP": "No", "MAPI": "No", "SMB": "No", "Key Exchange": "Encrypted Key Exchange", "Stego": "No", "Proxy Aware": "Yes", "DomainFront": "Yes", "Custom Profile": "Yes", "Jitter": "Yes", "Working Hours": "Yes", "Kill Date": "Yes", "Chaining": "No", "Logging": "Yes", "ATT&CK Mapping": "Yes", "Dashboard": "No", "NetWitness": "Yes", "Actively Maint.": "Yes", "Slack": "#psempire bloodhoundhq.slack.com", "Slack Members": "1299", "GH Issues": "61", "Notes": ""}}
```

# C2 Matrix Properties


* HTTP: Yes

* Implementation: install.sh

* Custom Profile: Yes

* DomainFront: Yes

* Multi-User: Yes

* SMB: No

* Kill Date: Yes

* macOS: Yes

* GitHub: https://github.com/BC-SECURITY/Empire

* Key Exchange: Encrypted Key Exchange

* Chaining: No

* Price: NA

* TCP: No

* Proxy Aware: Yes

* HTTP3: No

* HTTP2: No

* Date: 1/30/2020

* Evaluator: @jorgeorchilles

* Working Hours: Yes

* Slack: #psempire bloodhoundhq.slack.com

* FTP: No

* Logging: Yes

* Name: Empire

* License: BSD3

* Windows: Yes

* Stego: No

* Server: Python

* Actively Maint.: Yes

* Dashboard: No

* DNS: No

* ICMP: No

* IMAP: No

* DoH: No

* Jitter: Yes

* How-To: Yes

* ATT&CK Mapping: Yes

* Kali: Yes

* Twitter: @BCSecurity1

* MAPI: No

* Agent: PowerShell

* API: Yes

* UI: Web

* Linux: Yes
 

# Techniques


* [Browser Bookmark Discovery](../techniques/Browser-Bookmark-Discovery.md)

* [Input Capture](../techniques/Input-Capture.md)
    
* [Credentials in Files](../techniques/Credentials-in-Files.md)
    
* [Credential Dumping](../techniques/Credential-Dumping.md)
    
* [Video Capture](../techniques/Video-Capture.md)
    
* [Scripting](../techniques/Scripting.md)
    
* [Process Injection](../techniques/Process-Injection.md)
    
* [File and Directory Discovery](../techniques/File-and-Directory-Discovery.md)
    
* [Clipboard Data](../techniques/Clipboard-Data.md)
    
* [Pass the Ticket](../techniques/Pass-the-Ticket.md)
    
* [Private Keys](../techniques/Private-Keys.md)
    
* [Kerberoasting](../techniques/Kerberoasting.md)
    
* [Screen Capture](../techniques/Screen-Capture.md)
    
* [Network Sniffing](../techniques/Network-Sniffing.md)
    
* [LLMNR/NBT-NS Poisoning and Relay](../techniques/LLMNR-NBT-NS-Poisoning-and-Relay.md)
    
* [Hooking](../techniques/Hooking.md)
    
* [Command-Line Interface](../techniques/Command-Line-Interface.md)
    
* [PowerShell](../techniques/PowerShell.md)
    
* [Service Execution](../techniques/Service-Execution.md)
    
* [Trusted Developer Utilities](../techniques/Trusted-Developer-Utilities.md)
    
* [Component Object Model and Distributed COM](../techniques/Component-Object-Model-and-Distributed-COM.md)
    
* [Exploitation of Remote Services](../techniques/Exploitation-of-Remote-Services.md)
    
* [Access Token Manipulation](../techniques/Access-Token-Manipulation.md)
    
* [Pass the Hash](../techniques/Pass-the-Hash.md)
    
* [Remote Services](../techniques/Remote-Services.md)
    
* [Scheduled Task](../techniques/Scheduled-Task.md)
    
* [Windows Management Instrumentation](../techniques/Windows-Management-Instrumentation.md)
    
* [Accessibility Features](../techniques/Accessibility-Features.md)
    
* [Network Service Scanning](../techniques/Network-Service-Scanning.md)
    
* [DLL Search Order Hijacking](../techniques/DLL-Search-Order-Hijacking.md)
    
* [Path Interception](../techniques/Path-Interception.md)
    
* [Modify Existing Service](../techniques/Modify-Existing-Service.md)
    
* [Exploitation for Privilege Escalation](../techniques/Exploitation-for-Privilege-Escalation.md)
    
* [Security Support Provider](../techniques/Security-Support-Provider.md)
    
* [Bypass User Account Control](../techniques/Bypass-User-Account-Control.md)
    
* [SID-History Injection](../techniques/SID-History-Injection.md)
    
* [Shortcut Modification](../techniques/Shortcut-Modification.md)
    
* [Create Account](../techniques/Create-Account.md)
    
* [Data Compressed](../techniques/Data-Compressed.md)
    
* [Email Collection](../techniques/Email-Collection.md)
    
* [Timestomp](../techniques/Timestomp.md)
    
* [Registry Run Keys / Startup Folder](../techniques/Registry-Run-Keys---Startup-Folder.md)
    
* [Account Discovery](../techniques/Account-Discovery.md)
    
* [Standard Application Layer Protocol](../techniques/Standard-Application-Layer-Protocol.md)
    
* [Commonly Used Port](../techniques/Commonly-Used-Port.md)
    
* [Exfiltration Over Alternative Protocol](../techniques/Exfiltration-Over-Alternative-Protocol.md)
    
* [Exfiltration Over Command and Control Channel](../techniques/Exfiltration-Over-Command-and-Control-Channel.md)
    
* [Network Share Discovery](../techniques/Network-Share-Discovery.md)
    
* [Process Discovery](../techniques/Process-Discovery.md)
    
* [System Network Connections Discovery](../techniques/System-Network-Connections-Discovery.md)
    
* [System Network Configuration Discovery](../techniques/System-Network-Configuration-Discovery.md)
    
* [System Information Discovery](../techniques/System-Information-Discovery.md)
    
* [Security Software Discovery](../techniques/Security-Software-Discovery.md)
    
* [Standard Cryptographic Protocol](../techniques/Standard-Cryptographic-Protocol.md)
    
* [Remote File Copy](../techniques/Remote-File-Copy.md)
    
* [Execution through API](../techniques/Execution-through-API.md)
    
* [Obfuscated Files or Information](../techniques/Obfuscated-Files-or-Information.md)
    
* [Group Policy Modification](../techniques/Group-Policy-Modification.md)
    
* [Web Service](../techniques/Web-Service.md)
    
* [Domain Trust Discovery](../techniques/Domain-Trust-Discovery.md)
    
* [Credentials from Web Browsers](../techniques/Credentials-from-Web-Browsers.md)
    

# Actors


* [CopyKittens](../actors/CopyKittens.md)

* [FIN10](../actors/FIN10.md)
    
* [APT19](../actors/APT19.md)
    
* [APT33](../actors/APT33.md)
    
* [Turla](../actors/Turla.md)
    
* [WIRTE](../actors/WIRTE.md)
    
