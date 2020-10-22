
# Data from Removable Media

## Description

### MITRE Description

> Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information. 

Some adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on removable media.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1025

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['5140/5145', 'Net Shares']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['5140/5145', 'Net Shares']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations


* [Data from Removable Media Mitigation](../mitigations/Data-from-Removable-Media-Mitigation.md)


# Actors


* [APT28](../actors/APT28.md)

* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Turla](../actors/Turla.md)
    
* [Machete](../actors/Machete.md)
    
