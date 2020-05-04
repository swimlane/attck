
# Uncommonly Used Port

## Description

### MITRE Description

> Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls that have been improperly configured.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1065

## Potential Commands

```
Test-NetConnection -ComputerName #{domain} -port 8081

Test-NetConnection -ComputerName google.com -port #{port}

telnet #{domain} 8081

telnet google.com #{port}

```

## Commands Dataset

```
[{'command': 'Test-NetConnection -ComputerName #{domain} -port 8081\n',
  'name': None,
  'source': 'atomics/T1065/T1065.yaml'},
 {'command': 'Test-NetConnection -ComputerName google.com -port #{port}\n',
  'name': None,
  'source': 'atomics/T1065/T1065.yaml'},
 {'command': 'telnet #{domain} 8081\n',
  'name': None,
  'source': 'atomics/T1065/T1065.yaml'},
 {'command': 'telnet google.com #{port}\n',
  'name': None,
  'source': 'atomics/T1065/T1065.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls.': {'atomic_tests': [{'description': 'Testing '
                                                                                                                                                                  'uncommonly '
                                                                                                                                                                  'used '
                                                                                                                                                                  'port '
                                                                                                                                                                  'utilizing '
                                                                                                                                                                  'PowerShell. '
                                                                                                                                                                  'APT33 '
                                                                                                                                                                  'has '
                                                                                                                                                                  'been '
                                                                                                                                                                  'known '
                                                                                                                                                                  'to '
                                                                                                                                                                  'attempt '
                                                                                                                                                                  'telnet '
                                                                                                                                                                  'over '
                                                                                                                                                                  'port '
                                                                                                                                                                  '8081. '
                                                                                                                                                                  'Upon '
                                                                                                                                                                  'exectuion, '
                                                                                                                                                                  'details '
                                                                                                                                                                  'about '
                                                                                                                                                                  'the '
                                                                                                                                                                  'successful\n'
                                                                                                                                                                  'port '
                                                                                                                                                                  'check '
                                                                                                                                                                  'will '
                                                                                                                                                                  'be '
                                                                                                                                                                  'displayed.\n',
                                                                                                                                                   'executor': {'command': 'Test-NetConnection '
                                                                                                                                                                           '-ComputerName '
                                                                                                                                                                           '#{domain} '
                                                                                                                                                                           '-port '
                                                                                                                                                                           '#{port}\n',
                                                                                                                                                                'elevation_required': False,
                                                                                                                                                                'name': 'powershell'},
                                                                                                                                                   'input_arguments': {'domain': {'default': 'google.com',
                                                                                                                                                                                  'description': 'Specify '
                                                                                                                                                                                                 'target '
                                                                                                                                                                                                 'hostname',
                                                                                                                                                                                  'type': 'String'},
                                                                                                                                                                       'port': {'default': '8081',
                                                                                                                                                                                'description': 'Specify '
                                                                                                                                                                                               'uncommon '
                                                                                                                                                                                               'port '
                                                                                                                                                                                               'number',
                                                                                                                                                                                'type': 'String'}},
                                                                                                                                                   'name': 'Testing '
                                                                                                                                                           'usage '
                                                                                                                                                           'of '
                                                                                                                                                           'uncommonly '
                                                                                                                                                           'used '
                                                                                                                                                           'port '
                                                                                                                                                           'with '
                                                                                                                                                           'PowerShell',
                                                                                                                                                   'supported_platforms': ['windows']},
                                                                                                                                                  {'description': 'Testing '
                                                                                                                                                                  'uncommonly '
                                                                                                                                                                  'used '
                                                                                                                                                                  'port '
                                                                                                                                                                  'utilizing '
                                                                                                                                                                  'telnet.\n',
                                                                                                                                                   'executor': {'command': 'telnet '
                                                                                                                                                                           '#{domain} '
                                                                                                                                                                           '#{port}\n',
                                                                                                                                                                'elevation_required': False,
                                                                                                                                                                'name': 'sh'},
                                                                                                                                                   'input_arguments': {'domain': {'default': 'google.com',
                                                                                                                                                                                  'description': 'Specify '
                                                                                                                                                                                                 'target '
                                                                                                                                                                                                 'hostname',
                                                                                                                                                                                  'type': 'String'},
                                                                                                                                                                       'port': {'default': '8081',
                                                                                                                                                                                'description': 'Specify '
                                                                                                                                                                                               'uncommon '
                                                                                                                                                                                               'port '
                                                                                                                                                                                               'number',
                                                                                                                                                                                'type': 'String'}},
                                                                                                                                                   'name': 'Testing '
                                                                                                                                                           'usage '
                                                                                                                                                           'of '
                                                                                                                                                           'uncommonly '
                                                                                                                                                           'used '
                                                                                                                                                           'port',
                                                                                                                                                   'supported_platforms': ['linux',
                                                                                                                                                                           'macos']}],
                                                                                                                                 'attack_technique': 'T1065',
                                                                                                                                 'display_name': 'Adversaries '
                                                                                                                                                 'may '
                                                                                                                                                 'conduct '
                                                                                                                                                 'C2 '
                                                                                                                                                 'communications '
                                                                                                                                                 'over '
                                                                                                                                                 'a '
                                                                                                                                                 'non-standard '
                                                                                                                                                 'port '
                                                                                                                                                 'to '
                                                                                                                                                 'bypass '
                                                                                                                                                 'proxies '
                                                                                                                                                 'and '
                                                                                                                                                 'firewalls.'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations

None

# Actors


* [Group5](../actors/Group5.md)

* [APT3](../actors/APT3.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT32](../actors/APT32.md)
    
* [APT33](../actors/APT33.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
