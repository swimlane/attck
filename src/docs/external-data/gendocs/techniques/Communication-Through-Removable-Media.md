
# Communication Through Removable Media

## Description

### MITRE Description

> Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091). Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.

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
* Wiki: https://attack.mitre.org/techniques/T1092

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4657', 'Registry Monitoring ', 'USB Keys']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Data loss prevention']},
 {'data_source': ['4657', 'Registry Monitoring ', 'USB Keys']},
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


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Communication Through Removable Media Mitigation](../mitigations/Communication-Through-Removable-Media-Mitigation.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors


* [APT28](../actors/APT28.md)

