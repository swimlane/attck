
# Data Transfer Size Limits

## Description

### MITRE Description

> An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1030

## Potential Commands

```
cd /tmp/T1030; split -b 5000000 #{file_name}
ls -l /tmp/T1030

cd #{folder_path}; split -b 5000000 T1030_urandom
ls -l #{folder_path}

```

## Commands Dataset

```
[{'command': 'cd /tmp/T1030; split -b 5000000 #{file_name}\nls -l /tmp/T1030\n',
  'name': None,
  'source': 'atomics/T1030/T1030.yaml'},
 {'command': 'cd #{folder_path}; split -b 5000000 T1030_urandom\n'
             'ls -l #{folder_path}\n',
  'name': None,
  'source': 'atomics/T1030/T1030.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Data Transfer Size Limits': {'atomic_tests': [{'dependencies': [{'description': 'The '
                                                                                                          'file '
                                                                                                          'must '
                                                                                                          'exist '
                                                                                                          'for '
                                                                                                          'the '
                                                                                                          'test '
                                                                                                          'to '
                                                                                                          'run.',
                                                                                           'get_prereq_command': 'if '
                                                                                                                 '[ '
                                                                                                                 '! '
                                                                                                                 '-d '
                                                                                                                 '#{folder_path} '
                                                                                                                 ']; '
                                                                                                                 'then '
                                                                                                                 'mkdir '
                                                                                                                 '-p '
                                                                                                                 '#{folder_path}; '
                                                                                                                 'touch '
                                                                                                                 '#{folder_path}/safe_to_delete; '
                                                                                                                 'fi;      \n'
                                                                                                                 'dd '
                                                                                                                 'if=/dev/urandom '
                                                                                                                 'of=#{folder_path}/#{file_name} '
                                                                                                                 'bs=25000000 '
                                                                                                                 'count=1\n',
                                                                                           'prereq_command': 'if '
                                                                                                             '[ '
                                                                                                             '! '
                                                                                                             '-f '
                                                                                                             '#{folder_path}/#{file_name} '
                                                                                                             ']; '
                                                                                                             'then '
                                                                                                             'exit '
                                                                                                             '1; '
                                                                                                             'else '
                                                                                                             'exit '
                                                                                                             '0; '
                                                                                                             'fi;\n'}],
                                                                         'dependency_executor_name': 'sh',
                                                                         'description': 'Take '
                                                                                        'a '
                                                                                        'file/directory, '
                                                                                        'split '
                                                                                        'it '
                                                                                        'into '
                                                                                        '5Mb '
                                                                                        'chunks\n',
                                                                         'executor': {'cleanup_command': 'if '
                                                                                                         '[ '
                                                                                                         '-f '
                                                                                                         '#{folder_path}/safe_to_delete '
                                                                                                         ']; '
                                                                                                         'then '
                                                                                                         'rm '
                                                                                                         '-rf '
                                                                                                         '#{folder_path}; '
                                                                                                         'fi;\n',
                                                                                      'command': 'cd '
                                                                                                 '#{folder_path}; '
                                                                                                 'split '
                                                                                                 '-b '
                                                                                                 '5000000 '
                                                                                                 '#{file_name}\n'
                                                                                                 'ls '
                                                                                                 '-l '
                                                                                                 '#{folder_path}\n',
                                                                                      'elevation_required': False,
                                                                                      'name': 'sh'},
                                                                         'input_arguments': {'file_name': {'default': 'T1030_urandom',
                                                                                                           'description': 'File '
                                                                                                                          'name',
                                                                                                           'type': 'Path'},
                                                                                             'folder_path': {'default': '/tmp/T1030',
                                                                                                             'description': 'Path '
                                                                                                                            'where '
                                                                                                                            'the '
                                                                                                                            'test '
                                                                                                                            'creates '
                                                                                                                            'artifacts',
                                                                                                             'type': 'Path'}},
                                                                         'name': 'Data '
                                                                                 'Transfer '
                                                                                 'Size '
                                                                                 'Limits',
                                                                         'supported_platforms': ['macos',
                                                                                                 'linux']}],
                                                       'attack_technique': 'T1030',
                                                       'display_name': 'Data '
                                                                       'Transfer '
                                                                       'Size '
                                                                       'Limits'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations

None

# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

