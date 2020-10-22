
# Modify Authentication Process

## Description

### MITRE Description

> Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows or pluggable authentication modules (PAM) on Unix-based systems, responsible for gathering, storing, and validating credentials. 

Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows', 'Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1556

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)

* [Defense Evasion](../tactics/Defense-Evasion.md)
    

# Mitigations


* [Privileged Process Integrity](../mitigations/Privileged-Process-Integrity.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors

None
