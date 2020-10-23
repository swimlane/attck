
# System Firmware

## Description

### MITRE Description

> Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer. (Citation: Wikipedia BIOS) (Citation: Wikipedia UEFI) (Citation: About UEFI)

System firmware like BIOS and (U)EFI underly the functionality of a computer and may be modified by an adversary to perform or assist in malicious activity. Capabilities exist to overwrite the system firmware, which may give sophisticated adversaries a means to install malicious firmware updates as a means of persistence on a system that may be difficult to detect.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Host intrusion prevention systems', 'Anti-virus', 'File monitoring']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1542/001

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['BIOS']},
 {'data_source': ['EFI']},
 {'data_source': ['API monitoring']},
 {'data_source': ['BIOS']},
 {'data_source': ['EFI']},
 {'data_source': ['API monitoring']}]
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
    

# Mitigations


* [Boot Integrity](../mitigations/Boot-Integrity.md)

* [Update Software](../mitigations/Update-Software.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [System Firmware Mitigation](../mitigations/System-Firmware-Mitigation.md)
    

# Actors

None
