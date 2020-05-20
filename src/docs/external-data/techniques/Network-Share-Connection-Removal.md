
# Network Share Connection Removal

## Description

### MITRE Description

> Windows shared drive and [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) connections can be removed when no longer needed. [Net](https://attack.mitre.org/software/S0039) is an example utility that can be used to remove network share connections with the <code>net use \\system\share /delete</code> command. (Citation: Technet Net Use)

Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Host forensic analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1126

## Potential Commands

```
net use c: \\test\share
net share test=\\test\share /REMARK:"test share" /CACHE:No

net share \\test\share /delete

Remove-SmbShare -Name \\test\share
Remove-FileShare -Name \\test\share

```

## Commands Dataset

```
[{'command': 'net use c: \\\\test\\share\n'
             'net share test=\\\\test\\share /REMARK:"test share" /CACHE:No\n',
  'name': None,
  'source': 'atomics/T1126/T1126.yaml'},
 {'command': 'net share \\\\test\\share /delete\n',
  'name': None,
  'source': 'atomics/T1126/T1126.yaml'},
 {'command': 'Remove-SmbShare -Name \\\\test\\share\n'
             'Remove-FileShare -Name \\\\test\\share\n',
  'name': None,
  'source': 'atomics/T1126/T1126.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5140/5145', 'Net Shares']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['Packet capture']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5140/5145', 'Net Shares']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['Packet capture']}]
```

## Potential Queries

```json
[{'name': 'Network Share Connection Removal',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "net.exe"and '
           'process_command_line contains "net delete")or process_command_line '
           'contains "Remove-SmbShare"or process_command_line contains '
           '"Remove-FileShare"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Remove Network Share': {'atomic_tests': [{'auto_generated_guid': '14c38f32-6509-46d8-ab43-d53e32d2b131',
                                                                    'description': 'Add '
                                                                                   'a '
                                                                                   'Network '
                                                                                   'Share '
                                                                                   'utilizing '
                                                                                   'the '
                                                                                   'command_prompt\n',
                                                                    'executor': {'command': 'net '
                                                                                            'use '
                                                                                            'c: '
                                                                                            '#{share_name}\n'
                                                                                            'net '
                                                                                            'share '
                                                                                            'test=#{share_name} '
                                                                                            '/REMARK:"test '
                                                                                            'share" '
                                                                                            '/CACHE:No\n',
                                                                                 'elevation_required': False,
                                                                                 'name': 'command_prompt'},
                                                                    'input_arguments': {'share_name': {'default': '\\\\test\\share',
                                                                                                       'description': 'Share '
                                                                                                                      'to '
                                                                                                                      'add.',
                                                                                                       'type': 'string'}},
                                                                    'name': 'Add '
                                                                            'Network '
                                                                            'Share',
                                                                    'supported_platforms': ['windows']},
                                                                   {'auto_generated_guid': '09210ad5-1ef2-4077-9ad3-7351e13e9222',
                                                                    'description': 'Removes '
                                                                                   'a '
                                                                                   'Network '
                                                                                   'Share '
                                                                                   'utilizing '
                                                                                   'the '
                                                                                   'command_prompt\n',
                                                                    'executor': {'command': 'net '
                                                                                            'share '
                                                                                            '#{share_name} '
                                                                                            '/delete\n',
                                                                                 'elevation_required': False,
                                                                                 'name': 'command_prompt'},
                                                                    'input_arguments': {'share_name': {'default': '\\\\test\\share',
                                                                                                       'description': 'Share '
                                                                                                                      'to '
                                                                                                                      'remove.',
                                                                                                       'type': 'string'}},
                                                                    'name': 'Remove '
                                                                            'Network '
                                                                            'Share',
                                                                    'supported_platforms': ['windows']},
                                                                   {'auto_generated_guid': '0512d214-9512-4d22-bde7-f37e058259b3',
                                                                    'description': 'Removes '
                                                                                   'a '
                                                                                   'Network '
                                                                                   'Share '
                                                                                   'utilizing '
                                                                                   'PowerShell\n',
                                                                    'executor': {'command': 'Remove-SmbShare '
                                                                                            '-Name '
                                                                                            '#{share_name}\n'
                                                                                            'Remove-FileShare '
                                                                                            '-Name '
                                                                                            '#{share_name}\n',
                                                                                 'elevation_required': False,
                                                                                 'name': 'powershell'},
                                                                    'input_arguments': {'share_name': {'default': '\\\\test\\share',
                                                                                                       'description': 'Share '
                                                                                                                      'to '
                                                                                                                      'remove.',
                                                                                                       'type': 'string'}},
                                                                    'name': 'Remove '
                                                                            'Network '
                                                                            'Share '
                                                                            'PowerShell',
                                                                    'supported_platforms': ['windows']}],
                                                  'attack_technique': 'T1126',
                                                  'display_name': 'Remove '
                                                                  'Network '
                                                                  'Share'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

