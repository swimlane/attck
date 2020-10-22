
# Empire

## Description

### MITRE Description

> [Empire](https://attack.mitre.org/software/S0363) is an open source, cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python, the post-exploitation agents are written in pure [PowerShell](https://attack.mitre.org/techniques/T1086) for Windows and Python for Linux/macOS. [Empire](https://attack.mitre.org/software/S0363) was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries.(Citation: NCSC Joint Report Public Tools)(Citation: Github PowerShell Empire)(Citation: GitHub ATTACK Empire)

## Aliases

```
Empire
EmPyre
PowerShell Empire
```

## Additional Attributes

* Type: tool
* Wiki: https://attack.mitre.org/software/S0363

# C2 Matrix Dataset

```json
{"Empire": {"Name": "Empire", "License": "BSD3", "Price": "NA", "GitHub": "https://github.com/BC-SECURITY/Empire", "Site": "", "Twitter": "@BCSecurity1", "Evaluator": "@jorgeorchilles", "Date": "1/30/2020", "Version": "3.0.5", "Implementation": "install.sh", "How-To": "Yes", "Slingshot": "Yes", "Kali": "Yes", "Server": "Python", "Agent": "PowerShell", "Multi-User": "Yes", "UI": "GUI", "API": "Yes", "Windows": "Yes", "Linux": "Yes", "macOS": "Yes", "TCP": "No", "HTTP": "Yes", "HTTP2": "No", "HTTP3": "No", "DNS": "No", "DoH": "No", "ICMP": "No", "FTP": "No", "IMAP": "No", "MAPI": "No", "SMB": "No", "Key Exchange": "Encrypted Key Exchange", "Stego": "No", "Proxy Aware": "Yes", "DomainFront": "Yes", "Custom Profile": "Yes", "Jitter": "Yes", "Working Hours": "Yes", "Kill Date": "Yes", "Chaining": "No", "Logging": "Yes", "ATT&CK Mapping": "Yes", "Dashboard": "No", "NetWitness": "Yes", "Other": "", "Actively Maint.": "Yes", "Slack": "#psempire bloodhoundhq.slack.com", "Slack Members": "1299", "GH Issues": "61", "Notes": ""}}
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

* UI: GUI

* Linux: Yes
 

# Techniques


* [Browser Bookmark Discovery](../techniques/Browser-Bookmark-Discovery.md)

* [Keylogging](../techniques/Keylogging.md)
    
* [Credentials In Files](../techniques/Credentials-In-Files.md)
    
* [LSASS Memory](../techniques/LSASS-Memory.md)
    
* [Video Capture](../techniques/Video-Capture.md)
    
* [Windows Command Shell](../techniques/Windows-Command-Shell.md)
    
* [Process Injection](../techniques/Process-Injection.md)
    
* [File and Directory Discovery](../techniques/File-and-Directory-Discovery.md)
    
* [Clipboard Data](../techniques/Clipboard-Data.md)
    
* [Golden Ticket](../techniques/Golden-Ticket.md)
    
* [Private Keys](../techniques/Private-Keys.md)
    
* [Kerberoasting](../techniques/Kerberoasting.md)
    
* [Screen Capture](../techniques/Screen-Capture.md)
    
* [Network Sniffing](../techniques/Network-Sniffing.md)
    
* [LLMNR/NBT-NS Poisoning and SMB Relay](../techniques/LLMNR-NBT-NS-Poisoning-and-SMB-Relay.md)
    
* [Credential API Hooking](../techniques/Credential-API-Hooking.md)
    
* [Command and Scripting Interpreter](../techniques/Command-and-Scripting-Interpreter.md)
    
* [PowerShell](../techniques/PowerShell.md)
    
* [Service Execution](../techniques/Service-Execution.md)
    
* [Distributed Component Object Model](../techniques/Distributed-Component-Object-Model.md)
    
* [Exploitation of Remote Services](../techniques/Exploitation-of-Remote-Services.md)
    
* [Create Process with Token](../techniques/Create-Process-with-Token.md)
    
* [Pass the Hash](../techniques/Pass-the-Hash.md)
    
* [SSH](../techniques/SSH.md)
    
* [Scheduled Task](../techniques/Scheduled-Task.md)
    
* [Windows Management Instrumentation](../techniques/Windows-Management-Instrumentation.md)
    
* [Accessibility Features](../techniques/Accessibility-Features.md)
    
* [Network Service Scanning](../techniques/Network-Service-Scanning.md)
    
* [DLL Search Order Hijacking](../techniques/DLL-Search-Order-Hijacking.md)
    
* [Windows Service](../techniques/Windows-Service.md)
    
* [Exploitation for Privilege Escalation](../techniques/Exploitation-for-Privilege-Escalation.md)
    
* [Security Support Provider](../techniques/Security-Support-Provider.md)
    
* [Bypass User Access Control](../techniques/Bypass-User-Access-Control.md)
    
* [SID-History Injection](../techniques/SID-History-Injection.md)
    
* [Shortcut Modification](../techniques/Shortcut-Modification.md)
    
* [Local Account](../techniques/Local-Account.md)
    
* [Archive Collected Data](../techniques/Archive-Collected-Data.md)
    
* [Local Email Collection](../techniques/Local-Email-Collection.md)
    
* [Timestomp](../techniques/Timestomp.md)
    
* [Registry Run Keys / Startup Folder](../techniques/Registry-Run-Keys---Startup-Folder.md)
    
* [Domain Account](../techniques/Domain-Account.md)
    
* [Web Protocols](../techniques/Web-Protocols.md)
    
* [Commonly Used Port](../techniques/Commonly-Used-Port.md)
    
* [Exfiltration to Cloud Storage](../techniques/Exfiltration-to-Cloud-Storage.md)
    
* [Exfiltration Over C2 Channel](../techniques/Exfiltration-Over-C2-Channel.md)
    
* [Network Share Discovery](../techniques/Network-Share-Discovery.md)
    
* [Process Discovery](../techniques/Process-Discovery.md)
    
* [System Network Connections Discovery](../techniques/System-Network-Connections-Discovery.md)
    
* [System Network Configuration Discovery](../techniques/System-Network-Configuration-Discovery.md)
    
* [System Information Discovery](../techniques/System-Information-Discovery.md)
    
* [Security Software Discovery](../techniques/Security-Software-Discovery.md)
    
* [Asymmetric Cryptography](../techniques/Asymmetric-Cryptography.md)
    
* [Ingress Tool Transfer](../techniques/Ingress-Tool-Transfer.md)
    
* [Native API](../techniques/Native-API.md)
    
* [Obfuscated Files or Information](../techniques/Obfuscated-Files-or-Information.md)
    
* [Group Policy Modification](../techniques/Group-Policy-Modification.md)
    
* [Bidirectional Communication](../techniques/Bidirectional-Communication.md)
    
* [Domain Trust Discovery](../techniques/Domain-Trust-Discovery.md)
    
* [Credentials from Web Browsers](../techniques/Credentials-from-Web-Browsers.md)
    
* [Domain Account](../techniques/Domain-Account.md)
    
* [Exfiltration to Code Repository](../techniques/Exfiltration-to-Code-Repository.md)
    
* [Access Token Manipulation](../techniques/Access-Token-Manipulation.md)
    
* [Silver Ticket](../techniques/Silver-Ticket.md)
    
* [Local Account](../techniques/Local-Account.md)
    
* [Path Interception by PATH Environment Variable](../techniques/Path-Interception-by-PATH-Environment-Variable.md)
    
* [Path Interception by Search Order Hijacking](../techniques/Path-Interception-by-Search-Order-Hijacking.md)
    
* [Path Interception by Unquoted Path](../techniques/Path-Interception-by-Unquoted-Path.md)
    
* [MSBuild](../techniques/MSBuild.md)
    

# Actors


* [CopyKittens](../actors/CopyKittens.md)

* [FIN10](../actors/FIN10.md)
    
* [APT19](../actors/APT19.md)
    
* [APT33](../actors/APT33.md)
    
* [Turla](../actors/Turla.md)
    
* [WIRTE](../actors/WIRTE.md)
    
* [Silence](../actors/Silence.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
