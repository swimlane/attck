
# System Service Discovery

## Description

### MITRE Description

> Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are "sc," "tasklist /svc" using [Tasklist](https://attack.mitre.org/software/S0057), and "net start" using [Net](https://attack.mitre.org/software/S0039), but adversaries may also use other tools as well. Adversaries may use the information from [System Service Discovery](https://attack.mitre.org/techniques/T1007) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1007

## Potential Commands

```
tasklist.exe
sc query
sc query state= all

net.exe start >> C:\Windows\Temp\service-list.txt

{'windows': {'psh': {'command': 'Get-Service'}}}
```

## Commands Dataset

```
[{'command': 'tasklist.exe\nsc query\nsc query state= all\n',
  'name': None,
  'source': 'atomics/T1007/T1007.yaml'},
 {'command': 'net.exe start >> C:\\Windows\\Temp\\service-list.txt\n',
  'name': None,
  'source': 'atomics/T1007/T1007.yaml'},
 {'command': {'windows': {'psh': {'command': 'Get-Service'}}},
  'name': 'Identify system services',
  'source': 'data/abilities/discovery/c6607391-d02c-44b5-9b13-d3492ca58599.yml'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Timur Zinniatullin, oscd.community',
                  'date': '2019/10/21',
                  'description': 'Adversaries may interact with the Windows '
                                 'Registry to gather information about the '
                                 'system, configuration, and installed '
                                 'software.',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains': ['currentVersion\\windows',
                                                                       'currentVersion\\runServicesOnce',
                                                                       'currentVersion\\runServices',
                                                                       'winlogon\\',
                                                                       'currentVersion\\shellServiceObjectDelayLoad',
                                                                       'currentVersion\\runOnce',
                                                                       'currentVersion\\runOnceEx',
                                                                       'currentVersion\\run',
                                                                       'currentVersion\\policies\\explorer\\run',
                                                                       'currentcontrolset\\services'],
                                              'Image|endswith': '\\reg.exe'}},
                  'fields': ['Image',
                             'CommandLine',
                             'User',
                             'LogonGuid',
                             'Hashes',
                             'ParentProcessGuid',
                             'ParentCommandLine'],
                  'id': '970007b7-ce32-49d0-a4a4-fbef016950bd',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.discovery', 'attack.t1012', 'attack.t1007'],
                  'title': 'Query Registry'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5861', 'WMI']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5861', 'WMI']}]
```

## Potential Queries

```json
[{'name': 'System Service Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "net.exe"or '
           'process_path contains "tasklist.exe"or process_path contains '
           '"sc.exe"or process_path contains "wmic.exe")and (file_directory '
           'contains "net.exe\\" start"or file_directory contains '
           '"tasklist.exe\\" /SVC"and file_directory contains "sc.exe\\" '
           'query"or file_directory contains "wmic.exe\\" service where")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - System Service Discovery': {'atomic_tests': [{'auto_generated_guid': '89676ba1-b1f8-47ee-b940-2e1a113ebc71',
                                                                        'description': 'Identify '
                                                                                       'system '
                                                                                       'services.\n'
                                                                                       '\n'
                                                                                       'Upon '
                                                                                       'successful '
                                                                                       'execution, '
                                                                                       'cmd.exe '
                                                                                       'will '
                                                                                       'execute '
                                                                                       'service '
                                                                                       'commands '
                                                                                       'with '
                                                                                       'expected '
                                                                                       'result '
                                                                                       'to '
                                                                                       'stdout.\n',
                                                                        'executor': {'command': 'tasklist.exe\n'
                                                                                                'sc '
                                                                                                'query\n'
                                                                                                'sc '
                                                                                                'query '
                                                                                                'state= '
                                                                                                'all\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'command_prompt'},
                                                                        'name': 'System '
                                                                                'Service '
                                                                                'Discovery',
                                                                        'supported_platforms': ['windows']},
                                                                       {'auto_generated_guid': '5f864a3f-8ce9-45c0-812c-bdf7d8aeacc3',
                                                                        'description': 'Enumerates '
                                                                                       'started '
                                                                                       'system '
                                                                                       'services '
                                                                                       'using '
                                                                                       'net.exe '
                                                                                       'and '
                                                                                       'writes '
                                                                                       'them '
                                                                                       'to '
                                                                                       'a '
                                                                                       'file. '
                                                                                       'This '
                                                                                       'technique '
                                                                                       'has '
                                                                                       'been '
                                                                                       'used '
                                                                                       'by '
                                                                                       'multiple '
                                                                                       'threat '
                                                                                       'actors.\n'
                                                                                       '\n'
                                                                                       'Upon '
                                                                                       'successful '
                                                                                       'execution, '
                                                                                       'net.exe '
                                                                                       'will '
                                                                                       'run '
                                                                                       'from '
                                                                                       'cmd.exe '
                                                                                       'that '
                                                                                       'queries '
                                                                                       'services. '
                                                                                       'Expected '
                                                                                       'output '
                                                                                       'is '
                                                                                       'to '
                                                                                       'a '
                                                                                       'txt '
                                                                                       'file '
                                                                                       'in '
                                                                                       'c:\\Windows\\Temp\\service-list.txt.s\n',
                                                                        'executor': {'cleanup_command': 'del '
                                                                                                        '/f '
                                                                                                        '/q '
                                                                                                        '/s '
                                                                                                        '#{output_file} '
                                                                                                        '>nul '
                                                                                                        '2>&1\n',
                                                                                     'command': 'net.exe '
                                                                                                'start '
                                                                                                '>> '
                                                                                                '#{output_file}\n',
                                                                                     'name': 'command_prompt'},
                                                                        'input_arguments': {'output_file': {'default': 'C:\\Windows\\Temp\\service-list.txt',
                                                                                                            'description': 'Path '
                                                                                                                           'of '
                                                                                                                           'file '
                                                                                                                           'to '
                                                                                                                           'hold '
                                                                                                                           'net.exe '
                                                                                                                           'output',
                                                                                                            'type': 'Path'}},
                                                                        'name': 'System '
                                                                                'Service '
                                                                                'Discovery '
                                                                                '- '
                                                                                'net.exe',
                                                                        'supported_platforms': ['windows']}],
                                                      'attack_technique': 'T1007',
                                                      'display_name': 'System '
                                                                      'Service '
                                                                      'Discovery'}},
 {'Mitre Stockpile - Identify system services': {'description': 'Identify '
                                                                'system '
                                                                'services',
                                                 'id': 'c6607391-d02c-44b5-9b13-d3492ca58599',
                                                 'name': 'Discover system '
                                                         'services',
                                                 'platforms': {'windows': {'psh': {'command': 'Get-Service'}}},
                                                 'tactic': 'discovery',
                                                 'technique': {'attack_id': 'T1007',
                                                               'name': 'System '
                                                                       'Service '
                                                                       'Discovery'}}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [System Service Discovery Mitigation](../mitigations/System-Service-Discovery-Mitigation.md)


# Actors


* [Ke3chang](../actors/Ke3chang.md)

* [Turla](../actors/Turla.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [OilRig](../actors/OilRig.md)
    
* [APT1](../actors/APT1.md)
    
* [admin@338](../actors/admin@338.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
