
# Network Share Connection Removal

## Description

### MITRE Description

> Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) connections can be removed when no longer needed. [Net](https://attack.mitre.org/software/S0039) is an example utility that can be used to remove network share connections with the <code>net use \\system\share /delete</code> command. (Citation: Technet Net Use)

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
* Wiki: https://attack.mitre.org/techniques/T1070/005

## Potential Commands

```
Remove-SmbShare -Name \\test\share
Remove-FileShare -Name \\test\share
net use c: \\test\share
net share test=\\test\share /REMARK:"test share" /CACHE:No
net share \\test\share /delete
```

## Commands Dataset

```
[{'command': 'net use c: \\\\test\\share\n'
             'net share test=\\\\test\\share /REMARK:"test share" /CACHE:No\n',
  'name': None,
  'source': 'atomics/T1070.005/T1070.005.yaml'},
 {'command': 'net share \\\\test\\share /delete\n',
  'name': None,
  'source': 'atomics/T1070.005/T1070.005.yaml'},
 {'command': 'Remove-SmbShare -Name \\\\test\\share\n'
             'Remove-FileShare -Name \\\\test\\share\n',
  'name': None,
  'source': 'atomics/T1070.005/T1070.005.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Indicator Removal on Host: Network Share Connection Removal': {'atomic_tests': [{'auto_generated_guid': '14c38f32-6509-46d8-ab43-d53e32d2b131',
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
                                                                                         'attack_technique': 'T1070.005',
                                                                                         'display_name': 'Indicator '
                                                                                                         'Removal '
                                                                                                         'on '
                                                                                                         'Host: '
                                                                                                         'Network '
                                                                                                         'Share '
                                                                                                         'Connection '
                                                                                                         'Removal'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Network Share Connection Removal Mitigation](../mitigations/Network-Share-Connection-Removal-Mitigation.md)


# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

