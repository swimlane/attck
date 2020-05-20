
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
{"PoshC2": {"Name": "PoshC2", "License": "BSD3", "Price": "NA", "GitHub": "https://github.com/nettitude/PoshC2/", "Site": "https://poshc2.readthedocs.io/en/latest/", "Twitter": "@Nettitude_Labs", "Evaluator": "@jorgeorchilles", "Date": "11/13/2019", "Version": "5", "Implementation": "install.sh", "How-To": "", "Slingshot": "", "Kali": "Yes", "Server": "Python", "Agent": "PowerShell/C#/Python", "Multi-User": "Yes", "UI": "CLI", "API": "No", "Windows": "Yes", "Linux": "Yes", "macOS": "Yes", "TCP": "No", "HTTP": "Yes", "HTTP2": "No", "HTTP3": "No", "DNS": "No", "DoH": "No", "ICMP": "No", "FTP": "No", "IMAP": "No", "MAPI": "No", "SMB": "No", "Key Exchange": "TLS", "Stego": "No", "Proxy Aware": "Yes", "DomainFront": "Yes", "Custom Profile": "Yes", "Jitter": "Yes", "Working Hours": "No", "Kill Date": "Yes", "Chaining": "Yes", "Logging": "Yes", "ATT&CK Mapping": "Yes", "Dashboard": "No", "NetWitness": "Yes", "Actively Maint.": "Yes", "Slack": "poshc2.slack.com", "Slack Members": "NA", "GH Issues": "44", "Notes": ""}}
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

* Date: 11/13/2019

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
    
* [LLMNR/NBT-NS Poisoning and Relay](../techniques/LLMNR-NBT-NS-Poisoning-and-Relay.md)
    
* [Exploitation of Remote Services](../techniques/Exploitation-of-Remote-Services.md)
    
* [Automated Collection](../techniques/Automated-Collection.md)
    
* [Bypass User Account Control](../techniques/Bypass-User-Account-Control.md)
    
* [Input Capture](../techniques/Input-Capture.md)
    
* [Exploitation for Privilege Escalation](../techniques/Exploitation-for-Privilege-Escalation.md)
    
* [Process Injection](../techniques/Process-Injection.md)
    
* [Access Token Manipulation](../techniques/Access-Token-Manipulation.md)
    
* [Pass the Hash](../techniques/Pass-the-Hash.md)
    
* [Connection Proxy](../techniques/Connection-Proxy.md)
    
* [Windows Management Instrumentation Event Subscription](../techniques/Windows-Management-Instrumentation-Event-Subscription.md)
    
* [Windows Management Instrumentation](../techniques/Windows-Management-Instrumentation.md)
    
* [Credential Dumping](../techniques/Credential-Dumping.md)
    
* [Credentials in Files](../techniques/Credentials-in-Files.md)
    
* [Data Compressed](../techniques/Data-Compressed.md)
    
* [Service Execution](../techniques/Service-Execution.md)
    
* [System Service Discovery](../techniques/System-Service-Discovery.md)
    
* [System Network Connections Discovery](../techniques/System-Network-Connections-Discovery.md)
    
* [System Network Configuration Discovery](../techniques/System-Network-Configuration-Discovery.md)
    
* [System Information Discovery](../techniques/System-Information-Discovery.md)
    
* [Permission Groups Discovery](../techniques/Permission-Groups-Discovery.md)
    
* [Password Policy Discovery](../techniques/Password-Policy-Discovery.md)
    
* [Network Service Scanning](../techniques/Network-Service-Scanning.md)
    
* [Network Sniffing](../techniques/Network-Sniffing.md)
    
* [Account Discovery](../techniques/Account-Discovery.md)
    
* [File and Directory Discovery](../techniques/File-and-Directory-Discovery.md)
    
* [Standard Application Layer Protocol](../techniques/Standard-Application-Layer-Protocol.md)
    

# Actors


* [APT33](../actors/APT33.md)

