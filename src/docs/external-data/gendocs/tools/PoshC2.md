
# PoshC2

## Description

### MITRE Description

> [PoshC2](https://attack.mitre.org/software/S0378) is an open source remote administration and post-exploitation framework that is publicly available on GitHub. The server-side components of the tool are primarily written in Python, while the implants are written in [PowerShell](https://attack.mitre.org/techniques/T1086). Although [PoshC2](https://attack.mitre.org/software/S0378) is primarily focused on Windows implantation, it does contain a basic Python dropper for Linux/macOS.(Citation: GitHub PoshC2)

## Aliases

```
PoshC2
```

## Additional Attributes

* Type: tool
* Wiki: https://attack.mitre.org/software/S0378

# C2 Matrix Dataset

```json
{"PoshC2": {"Name": "PoshC2", "License": "BSD3", "Price": "NA", "GitHub": "https://github.com/nettitude/PoshC2/", "Site": "https://poshc2.readthedocs.io/en/latest/", "Twitter": "@Nettitude_Labs", "Evaluator": "@jorgeorchilles", "Date": "6/27/2020", "Version": "6", "Implementation": "install.sh", "How-To": "Yes", "Slingshot": "Possible", "Kali": "Yes", "Server": "Python", "Agent": "PowerShell/C#/Python", "Multi-User": "Yes", "UI": "CLI", "API": "No", "Windows": "Yes", "Linux": "Yes", "macOS": "Yes", "TCP": "No", "HTTP": "Yes", "HTTP2": "No", "HTTP3": "No", "DNS": "No", "DoH": "No", "ICMP": "No", "FTP": "No", "IMAP": "No", "MAPI": "No", "SMB": "No", "Key Exchange": "TLS", "Stego": "No", "Proxy Aware": "Yes", "DomainFront": "Yes", "Custom Profile": "Yes", "Jitter": "Yes", "Working Hours": "No", "Kill Date": "Yes", "Chaining": "Yes", "Logging": "Yes", "ATT&CK Mapping": "Yes", "Dashboard": "No", "NetWitness": "Yes", "Other": "Yes", "Actively Maint.": "Yes", "Slack": "poshc2.slack.com", "Slack Members": "NA", "GH Issues": "44", "Notes": ""}}
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

* GitHub: https://github.com/nettitude/PoshC2/

* Key Exchange: TLS

* Chaining: Yes

* Price: NA

* TCP: No

* Proxy Aware: Yes

* HTTP3: No

* HTTP2: No

* Date: 6/27/2020

* Evaluator: @jorgeorchilles

* Working Hours: No

* Slack: poshc2.slack.com

* FTP: No

* Logging: Yes

* Name: PoshC2

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

* Twitter: @Nettitude_Labs

* MAPI: No

* Site: https://poshc2.readthedocs.io/en/latest/

* Agent: PowerShell/C#/Python

* API: No

* UI: CLI

* Linux: Yes
 

# Techniques


* [Brute Force](../techniques/Brute-Force.md)

* [Domain Trust Discovery](../techniques/Domain-Trust-Discovery.md)
    
* [LLMNR/NBT-NS Poisoning and SMB Relay](../techniques/LLMNR-NBT-NS-Poisoning-and-SMB-Relay.md)
    
* [Exploitation of Remote Services](../techniques/Exploitation-of-Remote-Services.md)
    
* [Automated Collection](../techniques/Automated-Collection.md)
    
* [Bypass User Access Control](../techniques/Bypass-User-Access-Control.md)
    
* [Keylogging](../techniques/Keylogging.md)
    
* [Exploitation for Privilege Escalation](../techniques/Exploitation-for-Privilege-Escalation.md)
    
* [Process Injection](../techniques/Process-Injection.md)
    
* [Create Process with Token](../techniques/Create-Process-with-Token.md)
    
* [Pass the Hash](../techniques/Pass-the-Hash.md)
    
* [Proxy](../techniques/Proxy.md)
    
* [Windows Management Instrumentation Event Subscription](../techniques/Windows-Management-Instrumentation-Event-Subscription.md)
    
* [Windows Management Instrumentation](../techniques/Windows-Management-Instrumentation.md)
    
* [LSASS Memory](../techniques/LSASS-Memory.md)
    
* [Credentials In Files](../techniques/Credentials-In-Files.md)
    
* [Archive via Utility](../techniques/Archive-via-Utility.md)
    
* [Service Execution](../techniques/Service-Execution.md)
    
* [System Service Discovery](../techniques/System-Service-Discovery.md)
    
* [System Network Connections Discovery](../techniques/System-Network-Connections-Discovery.md)
    
* [System Network Configuration Discovery](../techniques/System-Network-Configuration-Discovery.md)
    
* [System Information Discovery](../techniques/System-Information-Discovery.md)
    
* [Local Groups](../techniques/Local-Groups.md)
    
* [Password Policy Discovery](../techniques/Password-Policy-Discovery.md)
    
* [Network Service Scanning](../techniques/Network-Service-Scanning.md)
    
* [Network Sniffing](../techniques/Network-Sniffing.md)
    
* [Domain Account](../techniques/Domain-Account.md)
    
* [File and Directory Discovery](../techniques/File-and-Directory-Discovery.md)
    
* [Web Protocols](../techniques/Web-Protocols.md)
    
* [Access Token Manipulation](../techniques/Access-Token-Manipulation.md)
    
* [Local Account](../techniques/Local-Account.md)
    

# Actors


* [APT33](../actors/APT33.md)

