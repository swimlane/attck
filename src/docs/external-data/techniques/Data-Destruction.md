
# Data Destruction

## Description

### MITRE Description

> Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018)(Citation: Talos Olympic Destroyer 2018) Common operating system file deletion commands such as <code>del</code> and <code>rm</code> often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) and [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.

Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable.(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018) In some cases politically oriented image files have been used to overwrite data.(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Talos Olympic Destroyer 2018)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'root', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1485

## Potential Commands

```
dd of=/var/log/syslog if=#{overwrite_source}
dd of=#{file_to_overwrite} if=/dev/zero
Invoke-Expression -Command "#{sdelete_exe} -accepteula $env:TEMP\T1485.txt"
Invoke-Expression -Command "$env:TEMP\Sdelete\sdelete.exe -accepteula #{file_to_delete}"
```

## Commands Dataset

```
[{'command': 'Invoke-Expression -Command "$env:TEMP\\Sdelete\\sdelete.exe '
             '-accepteula #{file_to_delete}"\n',
  'name': None,
  'source': 'atomics/T1485/T1485.yaml'},
 {'command': 'Invoke-Expression -Command "#{sdelete_exe} -accepteula '
             '$env:TEMP\\T1485.txt"\n',
  'name': None,
  'source': 'atomics/T1485/T1485.yaml'},
 {'command': 'dd of=#{file_to_overwrite} if=/dev/zero\n',
  'name': None,
  'source': 'atomics/T1485/T1485.yaml'},
 {'command': 'dd of=/var/log/syslog if=#{overwrite_source}\n',
  'name': None,
  'source': 'atomics/T1485/T1485.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Data Destruction': {'atomic_tests': [{'auto_generated_guid': '476419b5-aebf-4366-a131-ae3e8dae5fc2',
                                                                'dependencies': [{'description': 'Secure '
                                                                                                 'delete '
                                                                                                 'tool '
                                                                                                 'from '
                                                                                                 'Sysinternals '
                                                                                                 'must '
                                                                                                 'exist '
                                                                                                 'on '
                                                                                                 'disk '
                                                                                                 'at '
                                                                                                 'specified '
                                                                                                 'location '
                                                                                                 '(#{sdelete_exe})\n',
                                                                                  'get_prereq_command': 'Invoke-WebRequest '
                                                                                                        '"https://download.sysinternals.com/files/SDelete.zip" '
                                                                                                        '-OutFile '
                                                                                                        '"$env:TEMP\\SDelete.zip"\n'
                                                                                                        'Expand-Archive '
                                                                                                        '$env:TEMP\\SDelete.zip '
                                                                                                        '$env:TEMP\\Sdelete '
                                                                                                        '-Force\n'
                                                                                                        'Remove-Item '
                                                                                                        '$env:TEMP\\SDelete.zip '
                                                                                                        '-Force\n',
                                                                                  'prereq_command': 'if '
                                                                                                    '(Test-Path '
                                                                                                    '#{sdelete_exe}) '
                                                                                                    '{exit '
                                                                                                    '0} '
                                                                                                    'else '
                                                                                                    '{exit '
                                                                                                    '1}\n'},
                                                                                 {'description': 'The '
                                                                                                 'file '
                                                                                                 'to '
                                                                                                 'delete '
                                                                                                 'must '
                                                                                                 'exist '
                                                                                                 'at '
                                                                                                 '#{file_to_delete}\n',
                                                                                  'get_prereq_command': 'New-Item '
                                                                                                        '#{file_to_delete} '
                                                                                                        '-Force '
                                                                                                        '| '
                                                                                                        'Out-Null\n',
                                                                                  'prereq_command': 'if '
                                                                                                    '(Test-Path '
                                                                                                    '#{file_to_delete}) '
                                                                                                    '{ '
                                                                                                    'exit '
                                                                                                    '0 '
                                                                                                    '} '
                                                                                                    'else '
                                                                                                    '{ '
                                                                                                    'exit '
                                                                                                    '1 '
                                                                                                    '}\n'}],
                                                                'dependency_executor_name': 'powershell',
                                                                'description': 'Overwrites '
                                                                               'and '
                                                                               'deletes '
                                                                               'a '
                                                                               'file '
                                                                               'using '
                                                                               'Sysinternals '
                                                                               'SDelete. '
                                                                               'Upon '
                                                                               'successful '
                                                                               'execution, '
                                                                               '"Files '
                                                                               'deleted: '
                                                                               '1" '
                                                                               'will '
                                                                               'be '
                                                                               'displayed '
                                                                               'in\n'
                                                                               'the '
                                                                               'powershell '
                                                                               'session '
                                                                               'along '
                                                                               'with '
                                                                               'other '
                                                                               'information '
                                                                               'about '
                                                                               'the '
                                                                               'file '
                                                                               'that '
                                                                               'was '
                                                                               'deleted.\n',
                                                                'executor': {'command': 'Invoke-Expression '
                                                                                        '-Command '
                                                                                        '"#{sdelete_exe} '
                                                                                        '-accepteula '
                                                                                        '#{file_to_delete}"\n',
                                                                             'name': 'powershell'},
                                                                'input_arguments': {'file_to_delete': {'default': '$env:TEMP\\T1485.txt',
                                                                                                       'description': 'Path '
                                                                                                                      'of '
                                                                                                                      'file '
                                                                                                                      'to '
                                                                                                                      'delete',
                                                                                                       'type': 'path'},
                                                                                    'sdelete_exe': {'default': '$env:TEMP\\Sdelete\\sdelete.exe',
                                                                                                    'description': 'Path '
                                                                                                                   'of '
                                                                                                                   'sdelete '
                                                                                                                   'executable',
                                                                                                    'type': 'Path'}},
                                                                'name': 'Windows '
                                                                        '- '
                                                                        'Overwrite '
                                                                        'file '
                                                                        'with '
                                                                        'Sysinternals '
                                                                        'SDelete',
                                                                'supported_platforms': ['windows']},
                                                               {'auto_generated_guid': '38deee99-fd65-4031-bec8-bfa4f9f26146',
                                                                'description': 'Overwrites '
                                                                               'and '
                                                                               'deletes '
                                                                               'a '
                                                                               'file '
                                                                               'using '
                                                                               'DD.\n'
                                                                               'To '
                                                                               'stop '
                                                                               'the '
                                                                               'test, '
                                                                               'break '
                                                                               'the '
                                                                               'command '
                                                                               'with '
                                                                               'CTRL/CMD+C.\n',
                                                                'executor': {'command': 'dd '
                                                                                        'of=#{file_to_overwrite} '
                                                                                        'if=#{overwrite_source}\n',
                                                                             'name': 'bash'},
                                                                'input_arguments': {'file_to_overwrite': {'default': '/var/log/syslog',
                                                                                                          'description': 'Path '
                                                                                                                         'of '
                                                                                                                         'file '
                                                                                                                         'to '
                                                                                                                         'overwrite '
                                                                                                                         'and '
                                                                                                                         'remove',
                                                                                                          'type': 'Path'},
                                                                                    'overwrite_source': {'default': '/dev/zero',
                                                                                                         'description': 'Path '
                                                                                                                        'of '
                                                                                                                        'data '
                                                                                                                        'source '
                                                                                                                        'to '
                                                                                                                        'overwrite '
                                                                                                                        'with',
                                                                                                         'type': 'Path'}},
                                                                'name': 'macOS/Linux '
                                                                        '- '
                                                                        'Overwrite '
                                                                        'file '
                                                                        'with '
                                                                        'DD',
                                                                'supported_platforms': ['linux',
                                                                                        'macos']}],
                                              'attack_technique': 'T1485',
                                              'display_name': 'Data '
                                                              'Destruction'}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations


* [Data Destruction Mitigation](../mitigations/Data-Destruction-Mitigation.md)

* [Data Backup](../mitigations/Data-Backup.md)
    

# Actors


* [APT38](../actors/APT38.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
