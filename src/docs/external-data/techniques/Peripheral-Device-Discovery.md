
# Peripheral Device Discovery

## Description

### MITRE Description

> Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1120

## Potential Commands

```
system_profiler SPUSBDataType
```

## Commands Dataset

```
[{'command': 'system_profiler SPUSBDataType\n',
  'name': 'find attached usb devices',
  'source': 'data/abilities/discovery/9b007f62-daa1-44bd-a57d-00c5315ec6fe.yml'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - find attached usb devices': {'description': 'find '
                                                                 'attached usb '
                                                                 'devices',
                                                  'id': '9b007f62-daa1-44bd-a57d-00c5315ec6fe',
                                                  'name': 'USB Connected '
                                                          'Device Discovery',
                                                  'platforms': {'darwin': {'sh': {'command': 'system_profiler '
                                                                                             'SPUSBDataType\n'}}},
                                                  'tactic': 'discovery',
                                                  'technique': {'attack_id': 'T1120',
                                                                'name': 'Peripheral '
                                                                        'Device '
                                                                        'Discovery'}}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Peripheral Device Discovery Mitigation](../mitigations/Peripheral-Device-Discovery-Mitigation.md)


# Actors


* [APT28](../actors/APT28.md)

* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Equation](../actors/Equation.md)
    
* [APT37](../actors/APT37.md)
    
* [Turla](../actors/Turla.md)
    
