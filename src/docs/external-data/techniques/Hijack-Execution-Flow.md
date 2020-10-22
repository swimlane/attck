
# Hijack Execution Flow

## Description

### MITRE Description

> Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1574

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

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Restrict Library Loading](../mitigations/Restrict-Library-Loading.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Audit](../mitigations/Audit.md)
    
* [Update Software](../mitigations/Update-Software.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [User Account Control](../mitigations/User-Account-Control.md)
    
* [User Account Management](../mitigations/User-Account-Management.md)
    
* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)
    

# Actors

None
