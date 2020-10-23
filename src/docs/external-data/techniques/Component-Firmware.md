
# Component Firmware

## Description

### MITRE Description

> Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to [System Firmware](https://attack.mitre.org/techniques/T1542/001) but conducted upon other system components/devices that may not have the same capability or level of integrity checking.

Malicious component firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Host intrusion prevention systems', 'File monitoring']
* Effective Permissions: None
* Network: None
* Permissions: ['SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1542/002

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4663', 'File Monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4663', 'File Monitoring']}]
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


* [Component Firmware Mitigation](../mitigations/Component-Firmware-Mitigation.md)


# Actors


* [Equation](../actors/Equation.md)

