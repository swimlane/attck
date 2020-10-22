
# Replication Through Removable Media

## Description

### MITRE Description

> Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1091

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['219', ' 421', ' 4657', 'USB/PnP - IDs']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Data loss prevention']},
 {'data_source': ['4657', 'USB/PnP - IDs']},
 {'data_source': ['4657', 'Windows Registry']},
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


* [Initial Access](../tactics/Initial-Access.md)

* [Lateral Movement](../tactics/Lateral-Movement.md)
    

# Mitigations


* [Replication Through Removable Media Mitigation](../mitigations/Replication-Through-Removable-Media-Mitigation.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Limit Hardware Installation](../mitigations/Limit-Hardware-Installation.md)
    

# Actors


* [APT28](../actors/APT28.md)

* [Darkhotel](../actors/Darkhotel.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
