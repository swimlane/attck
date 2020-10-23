
# Non-Standard Port

## Description

### MITRE Description

> Adversaries may communicate using a protocol and port paring that are typically not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.

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
* Wiki: https://attack.mitre.org/techniques/T1571

## Potential Commands

```
telnet google.com #{port}
Test-NetConnection -ComputerName #{domain} -port 8081
telnet #{domain} 8081
Test-NetConnection -ComputerName google.com -port #{port}
```

## Commands Dataset

```
[{'command': 'Test-NetConnection -ComputerName #{domain} -port 8081\n',
  'name': None,
  'source': 'atomics/T1571/T1571.yaml'},
 {'command': 'Test-NetConnection -ComputerName google.com -port #{port}\n',
  'name': None,
  'source': 'atomics/T1571/T1571.yaml'},
 {'command': 'telnet #{domain} 8081\n',
  'name': None,
  'source': 'atomics/T1571/T1571.yaml'},
 {'command': 'telnet google.com #{port}\n',
  'name': None,
  'source': 'atomics/T1571/T1571.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Non-Standard Port': {'atomic_tests': [{'auto_generated_guid': '21fe622f-8e53-4b31-ba83-6d333c2583f4',
                                                                 'description': 'Testing '
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
                                                                                'execution, '
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
                                                                {'auto_generated_guid': '5db21e1d-dd9c-4a50-b885-b1e748912767',
                                                                 'description': 'Testing '
                                                                                'uncommonly '
                                                                                'used '
                                                                                'port '
                                                                                'utilizing '
                                                                                'telnet.\n',
                                                                 'executor': {'command': 'telnet '
                                                                                         '#{domain} '
                                                                                         '#{port}\n',
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
                                               'attack_technique': 'T1571',
                                               'display_name': 'Non-Standard '
                                                               'Port'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Network Segmentation](../mitigations/Network-Segmentation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    

# Actors


* [FIN7](../actors/FIN7.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [APT32](../actors/APT32.md)
    
* [APT33](../actors/APT33.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [APT-C-36](../actors/APT-C-36.md)
    
* [Silence](../actors/Silence.md)
    
* [DarkVishnya](../actors/DarkVishnya.md)
    
* [Rocke](../actors/Rocke.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
