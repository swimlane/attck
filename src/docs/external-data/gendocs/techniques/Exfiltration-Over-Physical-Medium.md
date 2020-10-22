
# Exfiltration Over Physical Medium

## Description

### MITRE Description

> Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

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
* Wiki: https://attack.mitre.org/techniques/T1052

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4657', 'Registry - USB Keys']},
 {'data_source': ['219', ' 441', 'Registry - USB/PnP IDs']},
 {'data_source': ['Data loss prevention']},
 {'data_source': ['File monitoring']},
 {'data_source': ['4657', 'Registry', 'USB Keys']},
 {'data_source': ['219', 'USB/PnP IDs']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Data loss prevention']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations


* [Exfiltration Over Physical Medium Mitigation](../mitigations/Exfiltration-Over-Physical-Medium-Mitigation.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Limit Hardware Installation](../mitigations/Limit-Hardware-Installation.md)
    

# Actors

None
