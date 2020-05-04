
# Peripheral Device Discovery

## Description

### MITRE Description

> Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1120

## Potential Commands

```
{'darwin': {'sh': {'command': 'system_profiler SPUSBDataType\n'}}}
```

## Commands Dataset

```
[{'command': {'darwin': {'sh': {'command': 'system_profiler SPUSBDataType\n'}}},
  'name': 'find attached usb devices',
  'source': 'data/abilities/discovery/9b007f62-daa1-44bd-a57d-00c5315ec6fe.yml'}]
```

## Potential Detections

```json

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

None

# Actors


* [APT28](../actors/APT28.md)

* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Equation](../actors/Equation.md)
    
* [APT37](../actors/APT37.md)
    
