
# Abuse Elevation Control Mechanism

## Description

### MITRE Description

> Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1548

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


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Control](../mitigations/User-Account-Control.md)

* [Audit](../mitigations/Audit.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors

None
