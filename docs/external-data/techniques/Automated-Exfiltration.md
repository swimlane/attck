
# Automated Exfiltration

## Description

### MITRE Description

> Data, such as sensitive documents, may be exfiltrated through the use of automated processing or [Scripting](https://attack.mitre.org/techniques/T1064) after being gathered during Collection. 

When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over Command and Control Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1020

## Potential Commands

```
powershell/exfiltration/egresscheck
powershell/exfiltration/egresscheck
```

## Commands Dataset

```
[{'command': 'powershell/exfiltration/egresscheck',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/exfiltration/egresscheck',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1020',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/exfiltration/egresscheck":  '
                                                                                 '["T1020"],',
                                            'Empire Module': 'powershell/exfiltration/egresscheck',
                                            'Technique': 'Automated '
                                                         'Exfiltration'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations

None

# Actors


* [Honeybee](../actors/Honeybee.md)

